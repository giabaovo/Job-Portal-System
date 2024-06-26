from django.contrib import admin
from django.urls import path, re_path, include

from rest_framework import permissions

from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="CatJob API",
        default_version='v1',
        description="API job referral system.",
        terms_of_service="",
        contact=openapi.Contact(email="giabaovo123456@gmail.com"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),

    path('admin/', admin.site.urls),
    path('api/', include(
        [
            path('auth/', include('authentication.urls')),
        ]
    ))
]
