# ADS-B repository agent notes

## Production-first delivery

- Deploy completed application changes to production as part of finishing the task. Ansel has authorized routine deployments for this repository; do not stop at a local implementation or ask for deployment confirmation each time.
- The user-facing stack is **https://adsb.ballydidean.farm**. Use the production URL in completion reports, normally **https://adsb.ballydidean.farm/map/** or **https://adsb.ballydidean.farm/admin**. A local preview is not delivery.
- Run local application/preview servers only while actively implementing, debugging, or validating a change. Stop task-owned local servers before finishing; do not leave an idle local stack running. Local unit tests and temporary isolated browser checks remain appropriate during active work.
- Validate changes before deployment, then verify the deployed release, production health, and affected public behavior. If deployment or verification is blocked, report the exact blocker rather than claiming completion.

## Deployment boundaries

- Follow `README.md` and the existing deployment scripts. The receiver is reached through the `adsb` SSH alias; `deploy/remote-stack.sh` provides the fixed production status/start/stop/restart operations.
- Deploy through the staged, immutable release installer in `deploy/install.sh`, preserving rollback artifacts. Do not hand-edit generated map assets, generated Compose files, or the selected immutable release.
- When staging under a restrictive umask, normalize public application-source permissions before installation (`chmod -R u=rwX,go=rX` on the staged `adsb_admin`, `web`, and `deploy` directories). The installer preserves source permissions, and the unprivileged admin service must be able to read the release. Keep the staging parent and all private configuration owner-only.
- Preserve station coordinates, network/feed choices and identifiers, private admin configuration, and tunnel credentials. Routine deployment authorization does not authorize changing secrets, enabling feeds, destructive maintenance, unrelated services, or Git commits/pushes.
- Keep unrelated dirty work intact and establish whether it is already deployed before including it in a release. Never send fixtures or simulated aircraft traffic to production/provider endpoints.
