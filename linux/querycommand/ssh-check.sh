#!/bin/bash
#==================================================================
# SSH 登录查询工具 - 全自动环境适配版 v2.0
# 增强：日志源空空检测、无数据友好提示、兼容无 journalctl 环境
#==================================================================
set -o pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

SUCCESS_LINES=20
FAILED_LINES=20
USER_FILTER=""
IP_FILTER=""
SINCE=""
UNTIL=""
SHOW_STATS=false
GEOIP=false
NO_COLOR=false
AUTO_SUDO=false

usage() {
    cat <<EOF
用法: $0 [选项]
选项:
  -s, --success <N>   成功记录数 (默认 20, 0 禁用)
  -f, --failed <N>    失败记录数 (默认 20, 0 禁用)
  -u, --user <USER>   按用户名过滤
  -i, --ip <IP>       按 IP 过滤
  --since <TIME>      起始时间 (journalctl 格式)
  --until <TIME>      结束时间
  --stats             显示暴力破解 IP 统计
  --geoip             查询 IP 归属地
  --no-color          禁用颜色
  --auto-sudo         无权限时自动 sudo
  -h, --help          帮助
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--success) SUCCESS_LINES="$2"; shift 2 ;;
        -f|--failed)  FAILED_LINES="$2"; shift 2 ;;
        -u|--user)    USER_FILTER="$2"; shift 2 ;;
        -i|--ip)      IP_FILTER="$2"; shift 2 ;;
        --since)      SINCE="$2"; shift 2 ;;
        --until)      UNTIL="$2"; shift 2 ;;
        --stats)      SHOW_STATS=true; shift ;;
        --geoip)      GEOIP=true; shift ;;
        --no-color)   NO_COLOR=true; shift ;;
        --auto-sudo)  AUTO_SUDO=true; shift ;;
        -h|--help)    usage ;;
        *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
    esac
done

$NO_COLOR && { RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''; }

geo_lookup() {
    local ip="$1"
    echo "$ip" | grep -Eq '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' && { echo "内网"; return; }
    if command -v geoiplookup &>/dev/null; then
        geoiplookup "$ip" 2>/dev/null | awk -F ': ' '{print $2}' | head -1
    elif command -v curl &>/dev/null; then
        curl -s --max-time 3 "http://ip-api.com/line/$ip?fields=country,city" | tr '\n' ', ' | sed 's/, $//'
    else
        echo "N/A"
    fi
}

# ---------- 权限 ----------
CMD_PREFIX=""
if [[ $EUID -ne 0 ]]; then
    if ! { journalctl -u sshd --no-pager -n 1 &>/dev/null || journalctl -u ssh --no-pager -n 1 &>/dev/null || test -r /var/log/auth.log || test -r /var/log/secure; }; then
        if $AUTO_SUDO && command -v sudo &>/dev/null; then
            CMD_PREFIX="sudo"
            echo -e "${YELLOW}[提示] 使用 sudo 读取日志${NC}" >&2
        else
            echo -e "${RED}[错误] 无权限读取 SSH 日志，请用 sudo 或添加 --auto-sudo${NC}" >&2
            exit 1
        fi
    fi
fi

# ---------- 日志源检测（强调有实际数据）----------
USE_JOURNAL=false
LOG_FILE=""
SSH_SERVICE=""

# 尝试 journalctl，要求至少能输出 1 条日志行
if command -v journalctl &>/dev/null; then
    for svc in sshd ssh; do
        if $CMD_PREFIX journalctl -u "$svc" --no-pager -n 1 2>/dev/null | grep -q .; then
            SSH_SERVICE="$svc"
            USE_JOURNAL=true
            break
        fi
    done
fi

if ! $USE_JOURNAL; then
    # 按顺序尝试文本日志文件（要求存在且非空）
    for candidate in /var/log/auth.log /var/log/secure /var/log/messages; do
        if $CMD_PREFIX test -s "$candidate"; then
            LOG_FILE="$candidate"
            break
        fi
    done
    if [[ -z "$LOG_FILE" ]]; then
        echo -e "${RED}[错误] 未找到任何包含 SSH 日志的数据源。${NC}" >&2
        echo "请检查：" >&2
        echo "  - 是否已安装并启动 sshd 服务？" >&2
        echo "  - 日志文件路径是否为 /var/log/secure (CentOS) 或 /var/log/auth.log (Ubuntu) ？" >&2
        echo "  - 是否有过 SSH 登录活动？新服务器可能无记录。" >&2
        exit 1
    fi
fi

# 构建日志读取命令（使用临时文件避免 eval 引号问题）
if $USE_JOURNAL; then
    GET_LOG() {
        local args="-u $SSH_SERVICE --no-pager -o short"
        [[ -n "$SINCE" ]] && args="$args --since \"$SINCE\""
        [[ -n "$UNTIL" ]] && args="$args --until \"$UNTIL\""
        $CMD_PREFIX journalctl $args 2>/dev/null
    }
else
    GET_LOG() { $CMD_PREFIX cat "$LOG_FILE"; }
fi

# ---------- 解析函数 ----------
parse_success() {
    while IFS= read -r line; do
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        method=$(echo "$line" | sed -n 's/.*Accepted \([a-z-]*\).*/\1/p')
        user=$(echo "$line" | sed -n 's/.*for \([^ ]*\) from .*/\1/p')
        ip=$(echo "$line" | sed -n 's/.*from \([0-9.]*\).*/\1/p')
        port=$(echo "$line" | sed -n 's/.*port \([0-9]*\).*/\1/p')
        [[ -z "$method" ]] && method="unknown"
        [[ -z "$user" ]] && user="?"
        [[ -z "$ip" ]] && ip="?"
        [[ -z "$port" ]] && port="?"
        [[ -n "$USER_FILTER" && "$user" != "$USER_FILTER" ]] && continue
        [[ -n "$IP_FILTER" && "$ip" != "$IP_FILTER" ]] && continue
        geo=""
        $GEOIP && [[ "$ip" != "?" ]] && geo=" | $(geo_lookup "$ip")"
        printf "${GREEN}[成功]${NC} %s | ${BLUE}用户: %s${NC} | IP: %s | 端口: %s | 方法: %s%s\n" \
            "$ts" "$user" "$ip" "$port" "$method" "$geo"
    done
}

parse_failed() {
    while IFS= read -r line; do
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        if echo "$line" | grep -q "Failed password"; then
            reason="密码错误"
            user=$(echo "$line" | sed -n 's/.*Failed password for \([^ ]*\) from .*/\1/p')
        elif echo "$line" | grep -q "Invalid user"; then
            reason="无效用户"
            user=$(echo "$line" | sed -n 's/.*Invalid user \([^ ]*\) from .*/\1/p')
        else
            reason="认证失败"
            user="?"
        fi
        ip=$(echo "$line" | sed -n 's/.*from \([0-9.]*\).*/\1/p')
        port=$(echo "$line" | sed -n 's/.*port \([0-9]*\).*/\1/p')
        [[ -z "$user" ]] && user="?"
        [[ -z "$ip" ]] && ip="?"
        [[ -z "$port" ]] && port="?"
        [[ -n "$USER_FILTER" && "$user" != "$USER_FILTER" ]] && continue
        [[ -n "$IP_FILTER" && "$ip" != "$IP_FILTER" ]] && continue
        geo=""
        $GEOIP && [[ "$ip" != "?" ]] && geo=" | $(geo_lookup "$ip")"
        printf "${RED}[失败]${NC} %s | ${YELLOW}用户: %s${NC} | IP: %s | 端口: %s | 原因: %s%s\n" \
            "$ts" "$user" "$ip" "$port" "$reason" "$geo"
    done
}

# ---------- 输出 ----------
NO_DATA_MSG="${YELLOW}[提示] 未查询到任何匹配的日志记录。${NC}"

if [[ $SUCCESS_LINES -gt 0 ]]; then
    echo -e "${GREEN}========== 最近 ${SUCCESS_LINES} 条成功登录 ==========${NC}"
    DATA=$(GET_LOG | grep "Accepted" | tail -n "$SUCCESS_LINES")
    if [[ -z "$DATA" ]]; then
        echo -e "$NO_DATA_MSG"
    else
        echo "$DATA" | parse_success
    fi
    echo
fi

if [[ $FAILED_LINES -gt 0 ]]; then
    echo -e "${RED}========== 最近 ${FAILED_LINES} 条失败登录 ==========${NC}"
    DATA=$(GET_LOG | grep -E "Failed password|Invalid user|authentication failure" | tail -n "$FAILED_LINES")
    if [[ -z "$DATA" ]]; then
        echo -e "$NO_DATA_MSG"
    else
        echo "$DATA" | parse_failed
    fi
    echo
fi

if $SHOW_STATS; then
    echo -e "${YELLOW}========== 失败登录 IP 统计 (Top 10) ==========${NC}"
    DATA=$(GET_LOG | grep -E "Failed password|Invalid user" | sed -n 's/.*from \([0-9.]*\).*/\1/p' | sort | uniq -c | sort -nr | head -10)
    if [[ -z "$DATA" ]]; then
        echo -e "$NO_DATA_MSG"
    else
        echo "$DATA" | while read count ip; do
            geo=""
            $GEOIP && geo=" | $(geo_lookup "$ip")"
            printf "${YELLOW}%-5s 次  ${CYAN}IP: %-18s${NC}%s\n" "$count" "$ip" "$geo"
        done
    fi
    echo
fi
