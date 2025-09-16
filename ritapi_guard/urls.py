"""
URL configuration for ritapi_guard project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from ritapi_guard.views import healthz, readyz

def home_redirect(request):
    if request.user.is_authenticated:
        return redirect("ops_dashboard")  # ke ops dashboard
    return redirect("login")

urlpatterns = [
    # auth
    path("login/", auth_views.LoginView.as_view(template_name="auth/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),
    
    path('admin/', admin.site.urls),
    
    path("healthz", healthz, name="healthz"),
    path("readyz", readyz, name="readyz"),
    
    # License Management will be handled by ops.urls
    
    # TLS Analyzer endpoints
    path("tls/", include("tls_analyzer.urls")),
    
    # ASN endpoints
    path("asn/", include("asn_score.urls")),
    
     # IP Reputation
    path("iprep/", include("ip_reputation.urls")),
    
    # ai behaviour profiler
    path("ai/", include("ai_behaviour.urls")),
    
    # JSON Enforcer
    path("json/", include("json_enforcer.urls")),
    
    # Alert Blocking
    path("alert_blocking/", include("alert_blocking.urls")),
    
    # ops dashboard
    path("ops/", include("ops.urls")),
    
    path("demo/", include("demo.urls")),
    
    path("", home_redirect, name="home_redirect"),

]

