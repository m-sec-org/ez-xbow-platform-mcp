FROM kalilinux/kali-rolling

ARG KALI_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/kali

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    printf 'deb %s kali-rolling main contrib non-free non-free-firmware\n' "$KALI_MIRROR" > /etc/apt/sources.list; \
    printf 'deb-src %s kali-rolling main contrib non-free non-free-firmware\n' "$KALI_MIRROR" >> /etc/apt/sources.list

# 基础工具
RUN apt-get update && apt-get -y install \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 必备开发/脚本环境
RUN apt-get update \
    && apt-get install -y \
        git \
        python3 \
        python3-pip \
        python3-venv \
        unzip \
        jq \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Node.js（如无需要可删除此段）
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Web 常用渗透工具（目录爆破、指纹、SSL 检测、注入测试、字典）
RUN apt-get update \
    && apt-get install -y \
        nmap \
        gobuster \
        whatweb \
        sslscan \
        sqlmap \
        seclists \
    && rm -rf /var/lib/apt/lists/*

# ncat / netcat
RUN apt-get update \
    && (apt-get install -y ncat || apt-get install -y netcat-openbsd || echo "No netcat variant available") \
    && rm -rf /var/lib/apt/lists/*

# rockyou（若未安装 wordlists，此命令会被忽略）
RUN gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# 如无需自定义安装，建议删除以下两段（可能重新拉入大量工具）
# COPY build/setup/ /tmp/setup/
# RUN chmod +x /tmp/setup/*.sh
# RUN for script in /tmp/setup/*.sh; do \
#         echo "Executing: $script"; \
#         bash "$script" || exit 1; \
#     done

# 清理
RUN rm -rf /tmp/setup /tmp/*.zip /tmp/*.deb /var/lib/apt/lists/*

RUN touch /root/THIS_IS_DOCKER_CONTAINER_NOT_TARGET_MACHINE.txt