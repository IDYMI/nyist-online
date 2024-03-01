
---

## 南阳理工学院 深澜校园网登录 Python 脚本

### 介绍

本 Python 脚本基于 [BIT-srun-login-script](https://github.com/coffeehat/BIT-srun-login-script)（北京理工大学深澜校园网登录 Python 脚本）。原项目包含基本的登录逻辑，本项目在此基础上加入了以下功能：

- 登出
- 检查登录状态
- 常在线

该脚本可以在任何支持 Python 的设备上运行，实现网络命令行登录或检查登录状态。脚本的主要文件包括：

- **LoginManager.py**: 程序主体。
- **LoginDemo.py**: 程序测试。
- **heartbeat.py**: 执行的操作代码。
- **main.py**: 实际定时任务的完整代码。

### 使用示例

- **登录**:

    ```bash
    python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=login
    ```

- **登出**:

    ```bash
    python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=logout
    ```

- **检查登录状态**:

    ```bash
    python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=check
    ```

- **保持常在线**:

    ```bash
    python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
    ```

### 安装和挂载

#### 1. 安装 Python

首先，确保系统中安装了 Python 3：

```bash
sudo apt-get update && sudo apt-get install python3
```

#### 2. 设置定时任务

使用 `cron` 设置定时任务，定期检查登录状态，并记录日志。

编辑 `cron` 配置文件：

```bash
sudo crontab -e
```

在 `crontab` 文件中添加以下任务：

```bash
* * * * * python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online >> /home/nyoj/workspace/nyist_network/heartbeat.log 2>&1
* * * * * sleep 5; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 10; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 15; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 20; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 25; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 30; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online >> /home/nyoj/workspace/nyist_network/heartbeat.log 2>&1
* * * * * sleep 35; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 40; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 45; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
* * * * * sleep 50; python3 /home/nyoj/workspace/nyist_network/main.py --config_file=/home/nyoj/workspace/nyist_network/setting.ini --option=online
```

### 更改账号信息

要修改登录账号信息，编辑 `setting.ini` 文件，更新默认的用户名和密码：

```ini
[DEFAULT]
username = ******  # 填入你的用户名
passwd = ******    # 填入你的密码
srun_ip = auth.nyist.edu.cn  # 填入认证服务器的 IP 地址
```

---
