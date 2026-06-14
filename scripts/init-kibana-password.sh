#!/bin/bash
echo "Waiting for Elasticsearch..."
until curl -s -u elastic:DetectionLab1! http://localhost:9200/_cluster/health | grep -q '"status"'; do
  sleep 5
done
echo "Setting kibana_system password..."
curl -s -u elastic:DetectionLab1! -X POST \
  "http://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d '{"password":"DetectionLab1!"}'
echo ""
echo "Done. Restart Kibana now:"
echo "docker restart kibana"
