import hmac
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, text
from sqlalchemy.exc import IntegrityError


BASE_DIR = Path(__file__).resolve().parent
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    kyc_verified = db.Column(db.Boolean, nullable=False, default=False)
    chargers = db.relationship("Charger", backref="host", lazy=True)


class Charger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(240), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    connector_type = db.Column(db.String(20), nullable=False)
    price_per_kwh = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, nullable=False, default=True)
    available_hours = db.Column(db.String(100), nullable=False, default="Available now")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    bookings = db.relationship("Booking", backref="charger", lazy=True)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    charger_id = db.Column(db.Integer, db.ForeignKey("charger.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    status = db.Column(db.String(12), nullable=False, default="active")
    total_amount = db.Column(db.Float, nullable=False)
    energy_kwh = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    driver = db.relationship("User", foreign_keys=[driver_id])


Index(
    "uq_active_booking_per_charger",
    Booking.charger_id,
    unique=True,
    sqlite_where=text("status = 'active'"),
)


def create_app():
    app = Flask(__name__, instance_path=str(BASE_DIR / "instance"))
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.update(
        SECRET_KEY=os.environ.get("COCHARGE_SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", f"sqlite:///{Path(app.instance_path, 'cocharge.db').as_posix()}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    db.init_app(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(self)")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; "
            "img-src 'self' data: blob: https://*.tile.openstreetmap.org; "
            "font-src 'self' data:; connect-src 'self' https://*.tile.openstreetmap.org; "
            "worker-src 'self'; manifest-src 'self';",
        )
        return response

    @app.before_request
    def enforce_api_csrf():
        if request.path.startswith("/api/") and request.method in {"POST", "PATCH", "DELETE"}:
            expected = session.get("csrf_token", "")
            supplied = request.headers.get("X-CSRF-Token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                return jsonify(error="Your session expired. Refresh the page and try again."), 403
        return None

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify(error="Request is too large."), 413

    @app.get("/")
    def index():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return render_template("index.html")

    def api_error(message, status=400):
        return jsonify(error=message), status

    def current_user():
        user_id = session.get("user_id")
        return db.session.get(User, user_id) if user_id else None

    def require_role(role):
        user = current_user()
        if user is None:
            return None, api_error("Set up your profile to continue.", 401)
        if user.role != role:
            return None, api_error(f"Switch your profile to {role} mode to continue.", 403)
        return user, None

    def valid_number(value, minimum, maximum):
        if isinstance(value, bool):
            return None
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if not (minimum <= number <= maximum):
            return None
        return number

    def charger_json(charger, distance_km=None):
        data = {
            "id": charger.id,
            "host_id": charger.host_id,
            "title": charger.title,
            "address": charger.address,
            "lat": charger.lat,
            "lng": charger.lng,
            "connector_type": charger.connector_type,
            "price_per_kwh": charger.price_per_kwh,
            "is_available": charger.is_available,
            "available_hours": charger.available_hours,
            "host_name": charger.host.name,
            "host_kyc_verified": charger.host.kyc_verified,
        }
        if distance_km is not None:
            data["distance_km"] = round(distance_km, 2)
        return data

    def booking_json(booking):
        return {
            "id": booking.id,
            "charger_id": booking.charger_id,
            "charger_title": booking.charger.title,
            "address": booking.charger.address,
            "lat": booking.charger.lat,
            "lng": booking.charger.lng,
            "status": booking.status,
            "total_amount": booking.total_amount,
            "energy_kwh": booking.energy_kwh,
            "payment_method": booking.payment_method,
            "timestamp": booking.timestamp.isoformat(),
            "driver_name": booking.driver.name,
            "host_name": booking.charger.host.name,
        }

    @app.get("/api/session")
    def get_session():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        user = current_user()
        return jsonify(
            csrf_token=session["csrf_token"],
            user=(
                {
                    "id": user.id,
                    "name": user.name,
                    "phone": user.phone,
                    "role": user.role,
                    "kyc_verified": user.kyc_verified,
                }
                if user
                else None
            ),
        )

    @app.post("/api/session")
    def save_session():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        phone_input = re.sub(r"[\s()-]", "", str(payload.get("phone", "")))
        phone_digits = phone_input.removeprefix("+91")
        role = payload.get("role")
        if not 2 <= len(name) <= 80:
            return api_error("Enter a name between 2 and 80 characters.")
        if not re.fullmatch(r"[6-9]\d{9}", phone_digits):
            return api_error("Enter a valid 10-digit Indian mobile number.")
        if role not in {"driver", "host"}:
            return api_error("Choose driver or host mode.")

        user = current_user()
        if user is None:
            user = User(name=name, phone=f"+91{phone_digits}", role=role)
            db.session.add(user)
        else:
            user.name = name
            user.phone = f"+91{phone_digits}"
            user.role = role
        db.session.commit()
        session["user_id"] = user.id
        return jsonify(user={"id": user.id, "name": user.name, "phone": user.phone, "role": user.role}), 200

    @app.get("/api/chargers")
    def get_chargers():
        lat = request.args.get("lat", type=float)
        lng = request.args.get("lng", type=float)
        radius = request.args.get("radius_km", type=float)
        if (lat is None) != (lng is None):
            return api_error("Provide both latitude and longitude.")
        if lat is not None and (not 6.0 <= lat <= 38.0 or not 68.0 <= lng <= 98.0):
            return api_error("Location must be within India.")
        if radius is not None and not 0.1 <= radius <= 100.0:
            return api_error("Radius must be between 0.1 and 100 km.")

        active_booking_ids = db.select(Booking.charger_id).where(Booking.status == "active")
        query = Charger.query.filter(
            Charger.is_available.is_(True),
            ~Charger.id.in_(active_booking_ids),
        )
        results = []
        for charger in query.all():
            distance = None
            if lat is not None and lng is not None:
                from math import asin, cos, radians, sin, sqrt

                lat1, lat2 = radians(lat), radians(charger.lat)
                delta_lat, delta_lng = lat2 - lat1, radians(charger.lng - lng)
                value = sin(delta_lat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(delta_lng / 2) ** 2
                distance = 6371 * 2 * asin(sqrt(min(1.0, value)))
                if radius is not None and distance > radius:
                    continue
            results.append(charger_json(charger, distance))
        if lat is not None:
            results.sort(key=lambda item: item["distance_km"])
        return jsonify(chargers=results)

    @app.post("/api/chargers/add")
    def add_charger():
        host, error = require_role("host")
        if error:
            return error
        payload = request.get_json(silent=True) or {}
        title = str(payload.get("title", "")).strip()
        address = str(payload.get("address", "")).strip()
        connector = payload.get("connector_type")
        hours = str(payload.get("available_hours", "Available now")).strip()
        lat = valid_number(payload.get("lat"), 6.0, 38.0)
        lng = valid_number(payload.get("lng"), 68.0, 98.0)
        price = valid_number(payload.get("price_per_kwh"), 0.1, 500.0)
        if not 3 <= len(title) <= 100:
            return api_error("Charger name must be between 3 and 100 characters.")
        if not 5 <= len(address) <= 240:
            return api_error("Enter an address between 5 and 240 characters.")
        if connector not in {"Type 2", "CCS2"}:
            return api_error("Choose a supported connector: Type 2 or CCS2.")
        if lat is None or lng is None:
            return api_error("Enter valid charger coordinates within India.")
        if price is None:
            return api_error("Set a price between ₹0.10 and ₹500 per kWh.")
        if not 3 <= len(hours) <= 100:
            return api_error("Enter availability hours between 3 and 100 characters.")

        charger = Charger(
            host_id=host.id,
            title=title,
            address=address,
            lat=lat,
            lng=lng,
            connector_type=connector,
            price_per_kwh=price,
            available_hours=hours,
            is_available=True,
        )
        db.session.add(charger)
        db.session.commit()
        return jsonify(charger=charger_json(charger)), 201

    @app.post("/api/book")
    def book_charger():
        driver, error = require_role("driver")
        if error:
            return error
        payload = request.get_json(silent=True) or {}
        charger_id = payload.get("charger_id")
        if isinstance(charger_id, bool) or not isinstance(charger_id, int):
            return api_error("Choose a valid charger.")
        energy = valid_number(payload.get("energy_kwh"), 0.1, 1000.0)
        if energy is None:
            return api_error("Energy must be between 0.1 and 1,000 kWh.")
        payment_method = payload.get("payment_method")
        if payment_method not in {"Google Pay", "PhonePe", "UPI"}:
            return api_error("Choose a supported simulated UPI method.")

        charger = db.session.get(Charger, charger_id)
        if charger is None or not charger.is_available:
            return api_error("This charger is no longer available.", 404)
        if charger.host_id == driver.id:
            return api_error("You cannot book your own charger.")
        if Booking.query.filter_by(charger_id=charger.id, status="active").first():
            return api_error("This charger has just been reserved. Choose another listing.", 409)

        booking = Booking(
            charger_id=charger.id,
            driver_id=driver.id,
            status="active",
            total_amount=round(energy * charger.price_per_kwh, 2),
            energy_kwh=energy,
            payment_method=payment_method,
        )
        db.session.add(booking)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return api_error("This charger has just been reserved. Choose another listing.", 409)
        return jsonify(booking=booking_json(booking)), 201

    @app.get("/api/bookings")
    def get_bookings():
        user = current_user()
        if user is None:
            return api_error("Set up your profile to continue.", 401)
        if user.role == "host":
            bookings = (
                Booking.query.join(Charger)
                .filter(Charger.host_id == user.id)
                .order_by(Booking.timestamp.desc())
                .limit(50)
                .all()
            )
        else:
            bookings = Booking.query.filter_by(driver_id=user.id).order_by(Booking.timestamp.desc()).limit(50).all()
        earnings = (
            db.session.query(db.func.coalesce(db.func.sum(Booking.total_amount), 0.0))
            .join(Charger)
            .filter(Charger.host_id == user.id, Booking.status == "completed")
            .scalar()
        ) if user.role == "host" else 0.0
        return jsonify(bookings=[booking_json(item) for item in bookings], completed_earnings=round(earnings, 2))

    @app.post("/api/bookings/<int:booking_id>/complete")
    def complete_booking(booking_id):
        host, error = require_role("host")
        if error:
            return error
        booking = db.session.get(Booking, booking_id)
        if booking is None or booking.charger.host_id != host.id:
            return api_error("Booking not found.", 404)
        if booking.status != "active":
            return api_error("This booking is already complete.", 409)
        booking.status = "completed"
        db.session.commit()
        return jsonify(booking=booking_json(booking))

    @app.post("/api/chargers/<int:charger_id>/availability")
    def toggle_availability(charger_id):
        host, error = require_role("host")
        if error:
            return error
        charger = db.session.get(Charger, charger_id)
        if charger is None or charger.host_id != host.id:
            return api_error("Charger not found.", 404)
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload.get("is_available"), bool):
            return api_error("Availability must be true or false.")
        charger.is_available = payload["is_available"]
        db.session.commit()
        return jsonify(charger=charger_json(charger))

    @app.get("/api/my-chargers")
    def my_chargers():
        host, error = require_role("host")
        if error:
            return error
        return jsonify(chargers=[charger_json(item) for item in Charger.query.filter_by(host_id=host.id).all()])

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
