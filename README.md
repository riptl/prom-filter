# PromQL filter

Work In Progress.

`prom-filter` is an experimental access control filter for the Prometheus API.

It runs as a standalone reverse proxy that filters and forwards requests to Prometheus.

**Motivation**

Exposing Grafana with a Prometheus data source to the world (anonymous auth) has security implications.
Grafana does not filter queries to data sources, leaving the entire Prometheus API exposed.

We want to restrict the random queries coming to Prometheus to only what's useful for Grafana dashboards.
