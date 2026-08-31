# Contributing to Aegis Scanner

Thanks for your interest in the project. Issues and pull requests are welcome.

Before you start on anything substantial, please open an issue to discuss it — it avoids
duplicated effort and saves you from building something that does not fit the project's
direction.

> Found a security vulnerability? Do not open a public issue.
> Follow [SECURITY.md](SECURITY.md) instead.

## Development setup

```bash
git clone https://github.com/deepakcybersecurity/Network-Security-Analyser.git
cd Network-Security-Analyser
```

```bash
python -m venv venv
```

Activate it (`source venv/bin/activate`, or `venv\Scripts\activate` on Windows), then:

```bash
pip install -r requirements.txt
```

Install [Nmap](https://nmap.org/download.html) if you intend to run live scans. The test
suite mocks it, so you can develop and test without it.

Run the app:

```bash
python app.py
```

## Running the tests

```bash
python -m unittest -v test_app.py
```

All seven tests must pass before you open a pull request. The suite uses a temporary
SQLite database and patches `app.scan_target`, so it never touches the network — please
keep it that way. **No test may perform a real scan or make a real network request.**

## Working on the styling

`static/css/style.css` is Tailwind build output and is committed so the app runs without a
Node toolchain. Never edit it by hand — edit `static/css/src.css` and rebuild:

```bash
npm install
```

```bash
npm run build:css
```

Commit both `src.css` and the regenerated `style.css`. CI rebuilds the stylesheet and fails
if the committed copy is stale. `npm run dev:css` watches for changes while you work.

## Code style

Match the surrounding code rather than introducing a new style.

**Python**

- 4-space indentation, `snake_case`, docstrings on every public function.
- Standard library imports first, then third-party, then local.
- Never interpolate user input into a SQL string — parameterise every statement.
- Never pass user input to a shell, and never use `shell=True`.
- Log failures with `logging` and return a generic message to the client. Raw exception
  text, file paths, and version strings must not reach a response body.
- `ruff check .` runs in CI as a report-only job. New code should not add findings.

**JavaScript**

- No new external dependencies, and no inline scripts — the CSP is `default-src 'self'`
  and must stay that way.
- Build DOM content with `textContent`, never `innerHTML`, for anything derived from API
  data.

**HTML / CSS**

- Tailwind utility classes in the markup; add custom CSS to `src.css` only when a utility
  cannot express it.

## Pull requests

1. Branch from `main` with a descriptive name (`fix/target-validation-ipv6`,
   `feat/udp-scan-option`).
2. Keep each pull request to one logical change. Unrelated fixes belong in separate PRs.
3. Add or update tests for any behaviour you change.
4. Update the README when you change a route, a configuration variable, or a security
   control.
5. Write commit messages in the imperative mood, explaining *why* rather than restating the
   diff. [Conventional Commits](https://www.conventionalcommits.org/) prefixes (`feat:`,
   `fix:`, `docs:`, `refactor:`, `test:`, `chore:`) are appreciated but not enforced.
6. Confirm the tests pass and fill in the pull request template.

## Changes that need discussion first

Open an issue before implementing any of these:

- Relaxing the target validation rules in `scanner.py`.
- Weakening or adding an exception to the Content Security Policy.
- Adding a Python or JavaScript dependency.
- Adding scan types beyond TCP connect — anything more aggressive changes the tool's risk
  profile and its legal footing for users.
- Removing or loosening the rate limit.

## Scope reminder

Aegis is an educational project about **defensive web application engineering**, using port
scanning as its subject matter. Contributions that harden the application, clarify the
documentation, or improve test coverage are the most valuable. Contributions that turn it
into an offensive toolkit — exploitation, evasion, credential attacks — are out of scope
and will be declined.

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE).
