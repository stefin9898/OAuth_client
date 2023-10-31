from django.shortcuts import render
import random, string, base64, hashlib, requests, json
import urllib.parse
from OAuth_client import settings

from .models import OAuthUser

ACCUKNOX_URL = "https://cspm." + settings.ENV + ".accuknox.com/api/v1/o/authorize/?"
TOKEN_URL = "https://cspm." + settings.ENV + ".accuknox.com/api/v1/o/token/"


def home(request):
    code_verifier = "".join(
        random.choice(string.ascii_uppercase + string.digits)
        for _ in range(random.randint(43, 128))
    )
    code_verifier = base64.urlsafe_b64encode(code_verifier.encode("utf-8"))

    code_challenge = hashlib.sha256(code_verifier).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge).decode("utf-8").replace("=", "")
    )

    oauth_user = OAuthUser.objects.create(
        code_verifier=code_verifier.decode("utf-8"),
        code_challenge=code_challenge,
    )
    redirect_uri = "http://127.0.0.1:8000/verify?user_id=" + oauth_user.id
    params = {
        "response_type": "code",
        "client_id": settings.CLIENT_ID,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    oauth_url = ACCUKNOX_URL + urllib.parse.urlencode(params)
    context = {"oauth_url": oauth_url, "user_id": oauth_user.id}
    return render(request, "index.html", context)


def verify(request):
    try:
        is_authenticated = False
        user_id = request.GET["user_id"]
        code = request.GET["code"]
        oauth_user = OAuthUser.objects.get(pk=user_id)
        headers = {
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        redirect_uri = "http://127.0.0.1:8000/verify?user_id=" + user_id
        data = (
            "redirect_uri="
            + redirect_uri
            + "&grant_type=authorization_code&client_id="
            + settings.CLIENT_ID
            + "&client_secret="
            + settings.CLIENT_SECRET
            + "&code="
            + code
            + "&code_verifier="
            + oauth_user.code_verifier
        )
        response = requests.post(TOKEN_URL, headers=headers, data=data)
        if response.status_code == 200:
            is_authenticated = True
        oauth_user.refresh_token = json.loads(response.text)["refresh_token"]
        oauth_user.jwt_token = json.loads(response.text)["access_token"]
        oauth_user.save()

    except Exception as e:
        print(e)
        pass
    context = {"is_authenticated": is_authenticated}
    if is_authenticated:
        context["user_id"] = request.GET["user_id"]
    return render(request, "verified.html", context)


def invoke(request):
    context = {}
    try:
        user_id = request.GET["user_id"]
        oauth_user = OAuthUser.objects.get(pk=user_id)
        headers = {
            "Authorization": "Bearer " + oauth_user.jwt_token,
        }
        # response = requests.get("https://cspm.dev.accuknox.com/api/v1/users/current-user-data", headers=headers)
        response = requests.get(
            "https://cspm." + settings.ENV + ".accuknox.com/api/v1/clients",
            headers=headers,
        )
        sources = requests.get(
            "https://cspm." + settings.ENV + ".accuknox.com/api/v1/sources/",
            headers=headers,
        )
        vuln = requests.get(
            "https://cspm."
            + settings.ENV
            + ".accuknox.com/api/v1/dashboard?data_type=SEVERITY_ISSUES&date_from=2023-09-10T11:04:41.204&date_to=2023-09-12T11:04:41.204&limit=10",
            headers=headers,
        )
        headers["Content-Type"] = "application/json"
        payload = {"cluster_id": [], "namespace_id": [], "type": []}
        workloads = requests.post(
            "https://cwpp." + settings.ENV + ".accuknox.com/cm/v2/get-workloads",
            headers=headers,
            data=json.dumps(payload),
        )
        print("CWPP API returned", workloads.status_code)
        if workloads.status_code == 200:
            context["tenants"] = json.loads(response.text)
            context["sources"] = json.loads(sources.text)["sources"]
            context["vuln"] = json.loads(vuln.content)["result"]["severity_issues"][
                "total_vulnerabilities"
            ]

        else:
            print("Refreshing Token!")
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            data = (
                "grant_type=refresh_token&client_id="
                + settings.CLIENT_ID
                + "&client_secret="
                + settings.CLIENT_SECRET
                + "&refresh_token="
                + oauth_user.refresh_token
            )
            response = requests.post(TOKEN_URL, headers=headers, data=data)
            if response.status_code == 200:
                oauth_user.refresh_token = json.loads(response.text)["refresh_token"]
                oauth_user.jwt_token = json.loads(response.text)["access_token"]
                oauth_user.save()
    except Exception as e:
        print(e)
        pass
    return render(request, "invoke.html", context)
