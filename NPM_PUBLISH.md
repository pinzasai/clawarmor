# npm Publish Checklist

## Pre-publish (do these in order)

- [ ] `npm login` (one-time, as pinzasai account — Alberto must run this)
- [ ] Bump version in `package.json` and all `lib/*.js` VERSION constants to match
- [ ] Run `node cli.js audit` — confirm it runs clean, no JS errors
- [ ] Run `node cli.js scan` — confirm it runs clean
- [ ] Run `node cli.js verify` — confirm it runs clean
- [ ] Check `package.json` has correct: name, version, description, bin, repository, homepage, license
- [ ] Confirm `.npmignore` or `files` field excludes: landing/, *.md research files, BRIEF.md, HN_LAUNCH.md
- [ ] Confirm `README.md` is publish-ready (has install instructions, feature list)

## Publish

```bash
npm publish --access public
```

## Post-publish

- [ ] Verify: `npm info clawarmor` shows correct version
- [ ] Test install: `npm install -g clawarmor@latest` in a temp dir
- [ ] Run `clawarmor --version` to confirm binary works
- [ ] Update MEMORY.md with publish date and npm package URL
- [ ] Post to HackerNews using HN_LAUNCH.md draft (best: Tue–Thu 9–11am ET)
- [ ] Submit to ClawHub registry (SKILL.md is ready)
- [ ] Push GitHub repo (needs GITHUB_TOKEN in agent env)

## What gets published

The package includes:
- cli.js
- lib/ (all check modules, scanner, output, probes)
- package.json
- README.md
- SECURITY.md
- SKILL.md

Does NOT include: landing/, BRIEF.md, HN_LAUNCH.md, NPM_PUBLISH.md
