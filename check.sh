#!/usr/bin/env bash

URL=http://localhost:9999/v1/check 

log() {
    echo ""
    echo ""
    echo -e "\e[31m==================================\e[0m"
    echo -e "\e[31m$1\e[0m"
    echo -e "\e[31m==================================\e[0m"
}

log "Employee viewing his own leave_request"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test01",
  "resource":  {
    "name":  "leave_request",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "john",
    "version":  "20200210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "view:public"
}
EOF

log "Employee approving his own leave_request"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test02",
  "resource":  {
    "name":  "leave_request",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "john",
    "version":  "20200210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "Direct manager approving leave_request"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test03",
  "resource":  {
    "name":  "leave_request",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "status":  "PENDING_APPROVAL",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "sally",
    "version":  "20200210",
    "roles":  [
      "employee",
      "manager"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "managed_geographies":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF

log "Manager from different geography approving leave_request"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test04",
  "resource":  {
    "name":  "leave_request",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "status":  "PENDING_APPROVAL",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "betty",
    "version":  "20200210",
    "roles":  [
      "employee",
      "manager"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "managed_geographies":  "FR",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "[Override for specific user] Donald Duck approving leave_request"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test05",
  "resource":  {
    "name":  "leave_request",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "dev_record":  true,
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "donald_duck",
    "version":  "20200210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "[Override for specific user] Donald Duck viewing salary record"
cat <<EOF | curl -i "$URL" -d @- 
{
  "requestId":  "test06",
  "resource":  {
    "name":  "salary_record",
    "version":  "20200210",
    "attr":  {
      "department":  "marketing",
      "dev_record":  true,
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "donald_duck",
    "version":  "20200210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "view"
}
EOF
