import hmac
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    kyc_verified = db.Column(db.Boolean, nullable=False, default=False)
    password_hash = db.Column(db.String(255), nullable=True)
    chargers = db.relationship("Charger", backref="host", lazy=True)


class CampaignAttribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    event_type = db.Column(db.String(30), nullable=False)
    source = db.Column(db.String(200), nullable=True)
    medium = db.Column(db.String(200), nullable=True)
    campaign = db.Column(db.String(200), nullable=True)
    term = db.Column(db.String(200), nullable=True)
    content = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


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
    reviews = db.relationship("Review", backref="charger", lazy=True)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    charger_id = db.Column(db.Integer, db.ForeignKey("charger.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="active")
    total_amount = db.Column(db.Float, nullable=False)
    energy_kwh = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    driver = db.relationship("User", foreign_keys=[driver_id])
    review = db.relationship("Review", backref="booking", uselist=False, lazy=True)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=False, unique=True)
    charger_id = db.Column(db.Integer, db.ForeignKey("charger.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


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
        template_path = Path(app.root_path, "templates", "index.html")
        last_updated = datetime.fromtimestamp(template_path.stat().st_mtime, timezone.utc).isoformat()
        response = app.make_response(render_template("index.html", last_updated=last_updated))
        response.headers["Cache-Control"] = "no-store"
        return response

    def api_error(message, status=400):
        return jsonify(error=message), status

    def current_user():
        user_id = session.get("user_id")
        return db.session.get(User, user_id) if user_id else None

    def record_attribution(user_id, event_type, payload):
        utm = payload.get("utm")
        if not isinstance(utm, dict):
            return
        values = {
            key: value.strip()[:200] if isinstance(value, str) else None
            for key, value in utm.items()
            if key in {"source", "medium", "campaign", "term", "content"}
        }
        if not any(values.values()):
            return
        db.session.add(CampaignAttribution(user_id=user_id, event_type=event_type, **values))

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
        reviews = Review.query.filter_by(charger_id=charger.id).all()
        avg_rating = round(sum(r.rating for r in reviews) / len(reviews), 1) if reviews else None
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
            "avg_rating": avg_rating,
            "review_count": len(reviews),
        }
        if distance_km is not None:
            data["distance_km"] = round(distance_km, 2)
        return data

    def review_json(review):
        return {
            "id": review.id,
            "rating": review.rating,
            "comment": review.comment,
            "driver_name": review.booking.driver.name,
            "created_at": review.created_at.isoformat(),
        }

    def booking_json(booking):
        data = {
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
            "has_review": booking.review is not None,
        }
        if booking.review:
            data["review"] = review_json(booking.review)
        return data

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
        if not isinstance(payload, dict):
            return api_error("Invalid profile details.")
        name = str(payload.get("name", "")).strip()
        phone_input = re.sub(r"[\s()-]", "", str(payload.get("phone", "")))
        phone_digits = phone_input.removeprefix("+91")
        password = payload.get("password")
        role = payload.get("role")
        if not 2 <= len(name) <= 80:
            return api_error("Enter a name between 2 and 80 characters.")
        if not re.fullmatch(r"[6-9]\d{9}", phone_digits):
            return api_error("Enter a valid 10-digit Indian mobile number.")
        if role not in {"driver", "host"}:
            return api_error("Choose driver or host mode.")

        user = current_user()
        normalized_phone = f"+91{phone_digits}"
        if user and user.phone != normalized_phone:
            return api_error("Sign out before switching to another account.", 409)
        if user is None:
            matching_users = User.query.filter_by(phone=normalized_phone).limit(2).all()
            if len(matching_users) > 1:
                return api_error("This phone number matches multiple legacy profiles. Contact support.", 409)
            user = matching_users[0] if matching_users else None
        if not isinstance(password, str):
            return api_error("Enter a password with at least 8 characters.")
        if len(password) > 128:
            return api_error("Password must be no more than 128 characters.")
        if user and user.password_hash:
            if not password or not check_password_hash(user.password_hash, password):
                return api_error("That phone number and password do not match.")
        elif password and len(password) < 8:
            return api_error("Password must be at least 8 characters.")
        elif not password and not (
            user and user.password_hash is None and session.get("user_id") == user.id
        ):
            return api_error("Set a password with at least 8 characters.")

        if user is None:
            user = User(name=name, phone=normalized_phone, role=role)
            db.session.add(user)
        else:
            user.name = name
            user.phone = normalized_phone
            user.role = role
        if password and not user.password_hash:
            user.password_hash = generate_password_hash(password)
        db.session.flush()
        record_attribution(user.id, "profile", payload)
        db.session.commit()
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["user_id"] = user.id
        return jsonify(
            csrf_token=session["csrf_token"],
            user={"id": user.id, "name": user.name, "phone": user.phone, "role": user.role},
        ), 200

    @app.post("/api/logout")
    def logout():
        session.pop("user_id", None)
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(csrf_token=session["csrf_token"])

    @app.get("/api/chargers")
    def get_chargers():
        lat = request.args.get("lat", type=float)
        lng = request.args.get("lng", type=float)
        radius = request.args.get("radius_km", type=float)
        connector_type = request.args.get("connector_type")
        max_price = request.args.get("max_price", type=float)
        search_query = request.args.get("q", "").strip().lower()

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
        if connector_type and connector_type in {"Type 2", "CCS2"}:
            query = query.filter(Charger.connector_type == connector_type)
        if max_price is not None and max_price > 0:
            query = query.filter(Charger.price_per_kwh <= max_price)

        results = []
        for charger in query.all():
            if search_query:
                if search_query not in charger.title.lower() and search_query not in charger.address.lower():
                    continue
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
        if not isinstance(payload, dict):
            return api_error("Invalid charger details.")
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
        record_attribution(host.id, "charger", payload)
        db.session.commit()
        return jsonify(charger=charger_json(charger)), 201

    @app.post("/api/book")
    def book_charger():
        driver, error = require_role("driver")
        if error:
            return error
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return api_error("Invalid booking details.")
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
        record_attribution(driver.id, "booking", payload)
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

    @app.post("/api/bookings/<int:booking_id>/cancel")
    def cancel_booking(booking_id):
        driver, error = require_role("driver")
        if error:
            return error
        booking = db.session.get(Booking, booking_id)
        if booking is None or booking.driver_id != driver.id:
            return api_error("Booking not found.", 404)
        if booking.status != "active":
            return api_error("Only active bookings can be cancelled.", 409)
        booking.status = "cancelled"
        db.session.commit()
        return jsonify(booking=booking_json(booking))

    @app.post("/api/bookings/<int:booking_id>/review")
    def review_booking(booking_id):
        driver, error = require_role("driver")
        if error:
            return error
        booking = db.session.get(Booking, booking_id)
        if booking is None or booking.driver_id != driver.id:
            return api_error("Booking not found.", 404)
        if booking.status != "completed":
            return api_error("You can only review completed bookings.", 400)
        if booking.review is not None:
            return api_error("You have already reviewed this booking.", 409)
        payload = request.get_json(silent=True) or {}
        rating = payload.get("rating")
        if not isinstance(rating, int) or not 1 <= rating <= 5:
            return api_error("Rating must be between 1 and 5.")
        comment = str(payload.get("comment", "")).strip()
        if len(comment) > 500:
            return api_error("Comment must be 500 characters or less.")
        review = Review(
            booking_id=booking.id,
            charger_id=booking.charger_id,
            driver_id=driver.id,
            rating=rating,
            comment=comment,
        )
        db.session.add(review)
        db.session.commit()
        return jsonify(review=review_json(review)), 201

    @app.get("/api/chargers/<int:charger_id>/reviews")
    def get_charger_reviews(charger_id):
        charger = db.session.get(Charger, charger_id)
        if charger is None:
            return api_error("Charger not found.", 404)
        reviews = Review.query.filter_by(charger_id=charger_id).order_by(Review.created_at.desc()).limit(50).all()
        return jsonify(reviews=[review_json(r) for r in reviews])

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

    @app.patch("/api/chargers/<int:charger_id>")
    def update_charger(charger_id):
        host, error = require_role("host")
        if error:
            return error
        charger = db.session.get(Charger, charger_id)
        if charger is None or charger.host_id != host.id:
            return api_error("Charger not found.", 404)
        payload = request.get_json(silent=True) or {}
        if "title" in payload:
            title = str(payload["title"]).strip()
            if not 3 <= len(title) <= 100:
                return api_error("Charger name must be between 3 and 100 characters.")
            charger.title = title
        if "address" in payload:
            address = str(payload["address"]).strip()
            if not 5 <= len(address) <= 240:
                return api_error("Enter an address between 5 and 240 characters.")
            charger.address = address
        if "connector_type" in payload:
            if payload["connector_type"] not in {"Type 2", "CCS2"}:
                return api_error("Connector type must be Type 2 or CCS2.")
            charger.connector_type = payload["connector_type"]
        if "price_per_kwh" in payload:
            price = valid_number(payload["price_per_kwh"], 0.1, 500.0)
            if price is None:
                return api_error("Price must be between ₹0.1 and ₹500.")
            charger.price_per_kwh = price
        if "available_hours" in payload:
            hours = str(payload["available_hours"]).strip()
            if not hours:
                return api_error("Available hours cannot be empty.")
            charger.available_hours = hours
        db.session.commit()
        return jsonify(charger=charger_json(charger))

    @app.delete("/api/chargers/<int:charger_id>")
    def delete_charger(charger_id):
        host, error = require_role("host")
        if error:
            return error
        charger = db.session.get(Charger, charger_id)
        if charger is None or charger.host_id != host.id:
            return api_error("Charger not found.", 404)
        active_booking = Booking.query.filter_by(charger_id=charger.id, status="active").first()
        if active_booking:
            return api_error("Cannot delete a charger with an active booking.", 409)
        Review.query.filter_by(charger_id=charger.id).delete()
        Booking.query.filter_by(charger_id=charger.id).delete()
        db.session.delete(charger)
        db.session.commit()
        return jsonify(success=True)

    @app.get("/api/my-chargers")
    def my_chargers():
        host, error = require_role("host")
        if error:
            return error
        return jsonify(chargers=[charger_json(item) for item in Charger.query.filter_by(host_id=host.id).all()])

    def seed_initial_data():
        if Charger.query.count() > 0:
            return
        host1 = User(name="Vikram Rao", phone="+919876543210", role="host", kyc_verified=True, password_hash=generate_password_hash("password123"))
        host2 = User(name="Pooja Sharma", phone="+919812345678", role="host", kyc_verified=True, password_hash=generate_password_hash("password123"))
        driver1 = User(name="Arjun Mehta", phone="+919988776655", role="driver", kyc_verified=False, password_hash=generate_password_hash("password123"))
        db.session.add_all([host1, host2, driver1])
        db.session.flush()

        chargers = [
            Charger(
                host_id=host1.id,
                title="Indiranagar 50kW Fast Hub",
                address="100ft Road, near Metro Station, Indiranagar, Bengaluru",
                lat=12.9784,
                lng=77.6408,
                connector_type="CCS2",
                price_per_kwh=18.5,
                is_available=True,
                available_hours="24/7",
            ),
            Charger(
                host_id=host1.id,
                title="Koramangala 7.4kW Driveway Charger",
                address="5th Block, near Sony World Junction, Koramangala, Bengaluru",
                lat=12.9352,
                lng=77.6245,
                connector_type="Type 2",
                price_per_kwh=13.0,
                is_available=True,
                available_hours="8:00 AM – 10:00 PM",
            ),
            Charger(
                host_id=host2.id,
                title="HSR Layout Sector 1 Fast Charging Point",
                address="14th Main, Sector 1, HSR Layout, Bengaluru",
                lat=12.9121,
                lng=77.6446,
                connector_type="CCS2",
                price_per_kwh=16.0,
                is_available=True,
                available_hours="6:00 AM – 11:00 PM",
            ),
            Charger(
                host_id=host2.id,
                title="Whitefield Tech Park Home Charger",
                address="ITPL Main Road, Brookefield, Whitefield, Bengaluru",
                lat=12.9698,
                lng=77.7500,
                connector_type="Type 2",
                price_per_kwh=14.0,
                is_available=True,
                available_hours="Available now",
            ),
        ]
        db.session.add_all(chargers)
        db.session.flush()

        b1 = Booking(
            charger_id=chargers[0].id,
            driver_id=driver1.id,
            status="completed",
            total_amount=370.0,
            energy_kwh=20.0,
            payment_method="Google Pay",
        )
        b2 = Booking(
            charger_id=chargers[1].id,
            driver_id=driver1.id,
            status="completed",
            total_amount=195.0,
            energy_kwh=15.0,
            payment_method="PhonePe",
        )
        db.session.add_all([b1, b2])
        db.session.flush()

        r1 = Review(
            booking_id=b1.id,
            charger_id=chargers[0].id,
            driver_id=driver1.id,
            rating=5,
            comment="Super fast charging and clean parking space. Host was very helpful!",
        )
        r2 = Review(
            booking_id=b2.id,
            charger_id=chargers[1].id,
            driver_id=driver1.id,
            rating=4,
            comment="Convenient location in Koramangala. Smooth experience.",
        )
        db.session.add_all([r1, r2])
        db.session.commit()

    with app.app_context():
        db.create_all()
        user_columns = {column["name"] for column in inspect(db.engine).get_columns("user")}
        if "password_hash" not in user_columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(255)"))
        seed_initial_data()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=os.environ.get("COCHARGE_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
