import paramiko
import time

from client import SSHJumpClient

with paramiko.SSHClient() as jumper:
    jumper.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jumper.connect(
        hostname='jump_host_ip_address',
        username='jump_host_username'
    )
    # Now instantiate a session for the Jump Host <-> Target
    # Host connection, and inject the jump_session to use for
    # proxying.
    with SSHJumpClient(jump_session=jumper) as target:
        target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        target.connect(
            hostname='target_host_ip_address',
            username='targer_host_username',
            password='target_host_password',
            look_for_keys=False,
            allow_agent=False,
        )
        with target.invoke_shell() as ssh:

            # Example

            time.sleep(1)
            ssh.recv(20000)
            ssh.send("\n")
            ssh.send("ip a\n")
            time.sleep(1)
            output = ssh.recv(10000).decode("utf-8")
            print(output)


