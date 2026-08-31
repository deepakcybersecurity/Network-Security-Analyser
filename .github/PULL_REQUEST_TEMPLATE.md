<!--
  Thanks for contributing. Please fill this in so the change can be reviewed quickly.

  Security vulnerabilities do not belong in a public pull request — see SECURITY.md.
-->

## Summary

<!-- What does this change, and why? Explain the motivation, not just the diff. -->

## Related issue

<!-- e.g. Closes #12 — open an issue first for anything substantial. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Tests / CI
- [ ] Dependency update

## How was this tested?

<!--
  Describe what you actually ran. If you added tests, say which. If you verified
  manually in the dashboard, say what you scanned — 127.0.0.1 only, please.
-->

```
python -m unittest -v test_app.py
```

- [ ] All existing tests pass
- [ ] I added or updated tests covering this change
- [ ] I verified the behaviour manually in the dashboard

## Checklist

- [ ] The change is one logical unit — unrelated fixes are in separate pull requests
- [ ] Code matches the surrounding style (see [CONTRIBUTING.md](https://github.com/deepakcybersecurity/Network-Security-Analyser/blob/main/CONTRIBUTING.md))
- [ ] No secrets, real scan output, internal hostnames, or `.env` files are committed
- [ ] Documentation is updated if this changes a route, config variable, or security control
- [ ] If I edited `static/css/src.css`, I ran `npm run build:css` and committed the output

## Security review

<!-- Delete this section if the change cannot affect any of the below. -->

- [ ] Any user input added or modified is validated before use
- [ ] All SQL remains parameterised — no string interpolation
- [ ] No user input reaches a shell, and `shell=True` is not used
- [ ] DOM content derived from API data uses `textContent`, not `innerHTML`
- [ ] Error responses stay generic; exception detail is logged server-side only
- [ ] The Content Security Policy is unchanged, or the change is explained below

<!-- Explain any security-relevant change here: -->

## Screenshots

<!-- For UI changes, before/after images. Redact any real hostname or IP. -->
