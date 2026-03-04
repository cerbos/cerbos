global:
  scrape_interval: 15s
scrape_configs:
  - job_name: "cerbos"
    scrape_interval: 7s
    metrics_path: /_cerbos/metrics
    static_configs:
      - targets: ["__PDP_IP__:3592"]
