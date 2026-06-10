# Run this once as a script: python create_demo_files.py
import pandas as pd

cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes',
        'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
        'num_shells','num_access_files','num_outbound_cmds','is_host_login',
        'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
        'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
        'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
        'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
        'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty']

df = pd.read_csv('data/KDDTest+.txt', names=cols)

# Save 10 normal rows
df[df['label'] == 'normal'].head(10).to_csv('demo/normal_traffic.csv', index=False, header=False)

# Save 10 attack rows
df[df['label'] == 'neptune'].head(10).to_csv('demo/attack_traffic.csv', index=False, header=False)

print("Demo files created in demo/ folder")
