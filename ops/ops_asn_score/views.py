import ipaddress
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from asn_score.models import AsnInfo, AsnTrustConfig
from asn_score.services import AsnScoreService


@login_required
def asn_checker(request):
    result = None
    error_message = None

    if request.method == "POST":
        ip = request.POST.get("ip")
        if ip:
            # ✅ Validate IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                error_message = f"'{ip}' is not a valid IP address."
            else:
                # ✅ Lookup ASN via service
                record = AsnScoreService.lookup_asn(ip)

                if record:
                    # ✅ Get trust score from config
                    trust_score = AsnScoreService.get_trust_score(record.asn_number)

                    # ✅ Update record with latest trust score
                    record.trust_score = trust_score
                    record.save(update_fields=["trust_score"])

                    result = record
                    messages.success(request, f"ASN for IP {ip} was found successfully.")
                else:
                    error_message = f"No ASN record found for IP {ip}."

    # ✅ History with pagination
    history_qs = AsnInfo.objects.all().order_by("-timestamp")
    paginator = Paginator(history_qs, 10)
    page_number = request.GET.get("page")
    history = paginator.get_page(page_number)

    # ✅ Config ASN with pagination
    configs_qs = AsnTrustConfig.objects.all().order_by("-updated_at")
    cfg_paginator = Paginator(configs_qs, 10)
    cfg_page = request.GET.get("cfg_page")
    configs = cfg_paginator.get_page(cfg_page)

    context = {
        "result": result,
        "error_message": error_message,  # pass to template
        "history": history,
        "configs": configs,
    }
    return render(request, "ops/asn_checker.html", context)

@login_required
def asn_update_score(request):
    if request.method == "POST":
        asn_number = request.POST.get("asn_number")
        name = request.POST.get("name", "")
        score = request.POST.get("score", 0)

        config, created = AsnTrustConfig.objects.update_or_create(
            asn_number=asn_number,
            defaults={"name": name, "score": score},
        )
        if created:
            messages.success(request, f"ASN {asn_number} berhasil ditambahkan dengan score {score}")
        else:
            messages.success(request, f"ASN {asn_number} berhasil diperbarui menjadi score {score}")

    return redirect("ops_asn_checker")
