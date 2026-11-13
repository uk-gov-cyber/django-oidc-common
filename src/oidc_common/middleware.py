from django.http import HttpResponse

HEALTH_CHECK_PATH = "/healthz/"


class HealthCheckMiddleware:
    """
    Answers the ALB target group health check before any other middleware
    runs. The ALB probes the task by private IP rather than by domain name,
    which would otherwise fail Django's ALLOWED_HOSTS check in
    CommonMiddleware - short-circuiting here means real traffic still gets
    full Host header validation, only this one fixed path is exempt.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == HEALTH_CHECK_PATH:
            return HttpResponse("OK")
        return self.get_response(request)
