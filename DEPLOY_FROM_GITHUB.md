# Deploy from GitHub

The included GitHub Actions workflow deploys `agent-harbour` to Fly.io whenever you push to the `main` branch.

1. From a terminal signed in to Fly.io, create a deploy token:

   ```bash
   fly tokens create deploy -n github-actions
   ```

2. In your GitHub repository, open **Settings → Secrets and variables → Actions**, create a repository secret named `FLY_API_TOKEN`, and paste the token as its value.

3. Push the repository to the `main` branch. GitHub Actions will build and deploy the app automatically.

Do not commit the token to the repository or put it in `fly.toml`.
