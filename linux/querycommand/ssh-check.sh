#!/bin/bash
#==================================================================
# SSH 登录查询工具 - 全自动环境适配版
# 自动检测 systemd/sysv、日志路径、权限，无需手动设置
# 用法：curl -fsSL <raw_url> | bash -s -- [选项]
#==================================================================
set -o pipefail

# 颜色定义
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# 默认参数
SUCCESS_LINES=20
FAILED_LINES=20
USER_FILTER=""
IP_FILTER=""
SINCE=""
UNTIL=""
SHOW_STATS=false
GEOIP=false
NO_COLOR=false
AUTO_SUDO=false   # 是否自动尝试 sudo

usage() {
    cat <<EOF
用法: $0 [选项]

选项:
  -s, --success <N>   成功记录数量 (默认 20, 0 禁用)
  -f, --failed <N>    失败记录数量 (默认 20, 0 禁用)
  -u, --user <USER>   按用户名过滤
  -i, --ip <IP>       按 IP 过滤
  --since <TIME>      起始时间 (journalctl 格式, 如 "1 hour ago")
  --until <TIME>      结束时间
  --stats             显示暴力破解统计 (IP 失败排名)
  --geoip             查询 IP 归属地 (需 geoiplookup 或 curl)
  --no-color          禁用颜色
  --auto-sudo         无权限时自动尝试提升权限 (需 sudo)
  -h, --help          显示帮助

示例:
  $0 -s 10 -f 10 --stats
  $0 --since "2 hours ago" --geoip
EOF
    exit 0
}

# 参数解析
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

# ---------- 环境自适应核心 ----------
check_dep() { command -v "$1" &>/dev/null; }
geo_lookup() {
    local ip="$1"
    [[ "$ip" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] && { echo "内网地址"; return; }
    if check_dep geoiplookup; then
        geoiplookup "$ip" 2>/dev/null | awk -F ': ' '{print $2}' | head -1
    elif check_dep curl; then
        curl -s --max-time 3 "http://ip-api.com/line/$ip?fields=country,city" | tr '\n' ', ' | sed 's/, $//'
    else
        echo "N/A"
    fi
}

# --- 1. 自动选择命令前缀 (处理 sudo) ---
CMD_PREFIX=""
if [[ $EUID -ne 0 ]]; then
    # 测试是否能读日志
    if ! { journalctl -u sshd --no-pager -n 1 &>/dev/null || \
           [[ -r /var/log/auth.log || -r /var/log/secure ]]; }; then
        if $AUTO_SUDO && check_dep sudo; then
            CMD_PREFIX="sudo"
            echo -e "${YELLOW}[提示] 使用 sudo 提升权限读取日志${NC}" >&2
        else
            echo -e "${RED}[错误] 无权限读取 SSH 日志，请使用 sudo 运行或添加 --auto-sudo${NC}" >&2
            exit 1
        fi
    fi
fi

# --- 2. 自动探测数据源 (journalctl 或日志文件) ---
USE_JOURNAL=false
LOG_FILE=""
# 检测 journalctl 是否可用且能读取 ssh 日志
SSH_SERVICE=""
if check_dep journalctl; then
    # 自动寻找 ssh 服务名
    for svc in sshd ssh; do
        if $CMD_PREFIX journalctl -u "$svc" --no-pager -n 1 &>/dev/null; then
            SSH_SERVICE="$svc"
            USE_JOURNAL=true
            break
        fi
    done
fi

if ! $USE_JOURNAL; then
    # 回退到文本日志
    for candidate in /var/log/auth.log /var/log/secure /var/log/messages; do
        if [[ -r "$candidate" ]] || $CMD_PREFIX test -r "$candidate"; then
            LOG_FILE="$candidate"
            break
        fi
    done
    if [[ -z "$LOG_FILE" ]]; then
        echo -e "${RED}[错误] 未找到可读的 SSH 日志文件${NC}" >&2
        exit 1
    fi
fi

# 构建日志读取命令
if $USE_JOURNAL; then
    BASE_CMD="$CMD_PREFIX journalctl -u $SSH_SERVICE --no-pager -o short-iso"
    [[ -n "$SINCE" ]] && BASE_CMD+=" --since \"$SINCE\""
    [[ -n "$UNTIL" ]] && BASE_CMD+=" --until \"$UNTIL\""
    GET_LOG() { eval "$BASE_CMD"; }
else
    BASE_CMD="$CMD_PREFIX cat $LOG_FILE"
    GET_LOG() { eval "$BASE_CMD"; }
fi

# --- 3. 日志解析辅助函数 ---
# 由于不同发行版 journalctl 输出格式可能略有不同，统一用正则提取
parse_success() {
    while IFS= read -r line; do
        # 提取时间：取行首的 ISO 时间 或 syslog 风格 "Mon DD HH:MM:SS"
        ts=$(echo "$line" | grep -oP '^\S+\s+\S+\s+\S+' 2>/dev/null || echo "$line" | awk '{print $1,$2,$3}')
        method=$(echo "$line" | grep -oP 'Accepted \K[a-z-]+' 2>/dev/null || echo "unknown")
        user=$(echo "$line" | grep -oP 'for \K[^ ]+' 2>/dev/null || echo "?")
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' 2>/dev/null || echo "?")
        port=$(echo "$line" | grep -oP 'port \K[0-9]+' 2>/dev/null || echo "?")
        # 用户/IP 过滤
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
        ts=$(echo "$line" | grep -oP '^\S+\s+\S+\s+\S+' 2>/dev/null || echo "$line" | awk '{print $1,$2,$3}')
        if echo "$line" | grep -q "Failed password"; then
            user=$(echo "$line" | grep -oP 'for \K[^ ]+' 2>/dev/null || echo "?")
            reason="密码错误"
        elif echo "$line" | grep -q "Invalid user"; then
            user=$(echo "$line" | grep -oP 'Invalid user \K[^ ]+' 2>/dev/null || echo "?")
            reason="无效用户"
        else
            user="?"; reason="认证失败"
        fi
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' 2>/dev/null || echo "?")
        port=$(echo "$line" | grep -oP 'port \K[0-9]+' 2>/dev/null || echo "?")
        [[ -n "$USER_FILTER" && "$user" != "$USER_FILTER" ]] && continue
        [[ -n "$IP_FILTER" && "$ip" != "$IP_FILTER" ]] && continue
        geo=""
        $GEOIP && [[ "$ip" != "?" ]] && geo=" | $(geo_lookup "$ip")"
        printf "${RED}[失败]${NC} %s | ${YELLOW}用户: %s${NC} | IP: %s | 端口: %s | 原因: %s%s\n" \
            "$ts" "$user" "$ip" "$port" "$reason" "$geo"
    done
}

# ---------- 输出 ----------
if [[ $SUCCESS_LINES -gt 0 ]]; then
    echo -e "${GREEN}========== 最近 ${SUCCESS_LINES} 条成功登录 ==========${NC}"
    GET_LOG | grep "Accepted" | tail -n "$SUCCESS_LINES" | parse_success
    echo
fi

if [[ $FAILED_LINES -gt 0 ]]; then
    echo -e "${RED}========== 最近 ${FAILED_LINES} 条失败登录 ==========${NC}"
    GET_LOG | grep -E "Failed password|Invalid user|authentication failure" | tail -n "$FAILED_LINES" | parse_failed
    echo
fi

if $SHOW_STATS; then
    echo -e "${YELLOW}========== 失败登录 IP 统计 (Top 10) ==========${NC}"
    GET_LOG | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -nr | head -10 | while read count ip; do
        geo=""
        $GEOIP && geo=" | $(geo_lookup "$ip")"
        printf "${YELLOW}%-5s 次  ${CYAN}IP: %-18s${NC}%s\n" "$count" "$ip" "$geo"
    done
    echo
fi
