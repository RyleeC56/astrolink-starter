from flask import Blueprint, render_template
from flask_login import login_required
from app.models import Subscriber
from app.permissions import permission_required

subscribers_bp = Blueprint("subscribers", __name__)

@subscribers_bp.route("/subscribers")
@login_required
@permission_required("view_subscribers")  # customer personal info: admins only
def list_subscribers():
    # Get every customer, sorted by name
    subscribers = Subscriber.query.order_by(Subscriber.full_name).all()
    return render_template("subscribers.html", subscribers=subscribers)