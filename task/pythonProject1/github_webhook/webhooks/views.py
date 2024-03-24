from django.http import HttpResponse, HttpResponseForbidden, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.conf import settings
from django.utils.encoding import force_bytes
import hmac
import hashlib
import json
import logging

# Настройка логирования
logging.basicConfig(filename='app.log', level=logging.INFO)

@require_POST
@csrf_exempt
def webhook(request):
    # Проверка подлинности запроса
    received_sign = request.META.get('HTTP_X_HUB_SIGNATURE')
    if received_sign is None:
        return HttpResponseForbidden()

    sha_name, signature = received_sign.split('=')
    if sha_name != 'sha1':
        return HttpResponseServerError()

    mac = hmac.new(force_bytes(settings.GITHUB_WEBHOOK_KEY), msg=force_bytes(request.body), digestmod=hashlib.sha1)
    if not hmac.compare_digest(force_bytes(mac.hexdigest()), force_bytes(signature)):
        return HttpResponseForbidden()

    # Обработка событий
    event = request.META.get('HTTP_X_GITHUB_EVENT', 'ping')
    payload = json.loads(request.body)

    if event == 'push':
        logging.info('Received push event: %s', json.dumps(payload, indent=4))
    elif event == 'pull_request':
        if payload['action'] == 'closed' and payload['pull_request']['merged']:
            logging.info('Received merge event: %s', json.dumps(payload, indent=4))

    return HttpResponse(status=200)