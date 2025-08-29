# ops/views.py
import ipaddress
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from ip_reputation.models import IpReputation
from ip_reputation.services import IpReputationService
from django.contrib import messages


@login_required
def ip_reputation_dashboard(request):
    """
    IP Reputation dashboard: check new IP + show history.
    """
    result = None
    error_message = None

    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        if ip_address:
            # ✅ Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                error_message = f"'{ip_address}' is not a valid IP address."
            else:
                result = IpReputationService.check_reputation(ip_address)
                if not result:
                    error_message = f"No reputation data found for IP {ip_address}."
                else:
                    messages.success(request, f"Reputation check for IP {ip_address} completed successfully.")

    # ✅ Fetch history with pagination
    records = IpReputation.objects.all().order_by("-timestamp")
    paginator = Paginator(records, 10)
    page_number = request.GET.get("page")
    history = paginator.get_page(page_number)

    return render(request, "ops/ip_reputation.html", {
        "result": result,
        "error_message": error_message,  # ✅ pass to template
        "history": history,
    })
