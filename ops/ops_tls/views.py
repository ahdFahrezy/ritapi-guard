from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from tls_analyzer.services import TlsAnalyzerService
from tls_analyzer.models import TlsAnalyzer


@login_required
def tls_dashboard(request):
    result = None
    error_message = None
    query = request.GET.get("q")  # filter by query string
    domain_filter = request.GET.get("domain")  # for history filter

    # Handle POST (new TLS analyze request)
    if request.method == "POST":
        domain = request.POST.get("domain")
        if domain:
            result = TlsAnalyzerService.get_or_analyze_tls(domain)
            if not result:
                error_message = f"No TLS data found for '{domain}'."

    # Handle GET search
    results = []
    if query:
        results = TlsAnalyzer.objects.filter(domain__icontains=query)
        if not results.exists():
            error_message = f"No TLS data found for '{query}'."

    # History (paginated)
    records = TlsAnalyzer.objects.all()
    if domain_filter:
        records = records.filter(hostname__icontains=domain_filter)

    records = records.order_by("-timestamp")
    paginator = Paginator(records, 10)
    page_number = request.GET.get("page")
    history = paginator.get_page(page_number)

    context = {
        "result": result,             # hasil dari POST analyze
        "results": results,           # hasil dari search
        "query": query,
        "error_message": error_message,
        "history": history,           # riwayat dengan pagination
        "domain_filter": domain_filter,
    }
    return render(request, "ops_template/tls_check.html", context)
    
    
@login_required
def tls_check_new(request):
    """
    Cek TLS lewat form POST → tampilkan hasil single domain
    """
    record = None

    if request.method == "POST":
        domain = request.POST.get("domain")
        if domain:
            record = TlsAnalyzerService.get_or_analyze_tls(domain)

    return render(request, "ops_template/tls_result.html", {
        "record": record
    })
