from gotauth import Principal
from gotauth.plugins.api_key import api_key

auth = GotAuth(
    ...,  # database, secret and base_url as above
    plugins=[api_key()],
)

CurrentPrincipal = Annotated[Principal, Depends(auth.fastapi.current_principal)]

@app.get("/projects")
async def list_projects(principal: CurrentPrincipal):
    ...  # a session, an API key or an OAuth access token
