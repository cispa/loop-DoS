If you want to check whether your server/software is affected, you can use the provided ```simple_verify.py``` script.

    python3 simple_verify.py <protocol> <server_ip>

    <protocol> : dns, ntp, tftp
    <server_ip> : ip of the tested server


The script will send a series of trigger probes identified in our experiment. Since all these trigger probes are responses/error messages that a server shall not react to, if you observe a response sent by your server, it likely suggets your server is affected.

Note that, some TFTP software would send a response from a random source port other than 69. If your server doesn't send a TFTP response from source port 69, it is likely not affected.