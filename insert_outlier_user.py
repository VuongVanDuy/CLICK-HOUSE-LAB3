import random
from datetime import datetime, timedelta
from clickhouse_driver import Client
import pandas as pd

# ==================== CẤU HÌNH ====================
CONFIG = {
    'clickhouse_host': 'localhost',
    'clickhouse_port': 9000,
    'database': 'default',
    'clickhouse_user': 'myuser',
    'clickhouse_password': 'mypassword',
    'table_name': 'security_events',
    'outlier_user_id': 999999,
    'outlier_factor': 5,
    'batch_size': 10000
}

def get_clickhouse_client() -> Client:
    return Client(
        host=CONFIG['clickhouse_host'],
        port=CONFIG['clickhouse_port'],
        database=CONFIG['database'],
        user=CONFIG['clickhouse_user'],
        password=CONFIG['clickhouse_password']
    )


def calculate_threshold(client):
    stats = client.execute("""
       WITH user_actions AS (SELECT user_id, COUNT(*) as actions
                             FROM security_events
                             GROUP BY user_id)
       SELECT AVG(actions), stddevPop(actions)
       FROM user_actions
       """)[0]
    return stats[0], stats[1], stats[0] + 3 * stats[1]


def get_time_range(client):
    date_range = client.execute("SELECT MIN(timestamp), MAX(timestamp) FROM security_events")[0]
    start, end = date_range[0], date_range[1] or datetime.now()
    if (end - start).days < 30:
        end = datetime.now()
        start = end - timedelta(days=90)
    return start, end

def create_event(timestamp, user_id):
    event_types = ['login', 'access', 'privilege_change']
    resources = ['/api/data', '/admin', '/dashboard', '/reports', '/settings']
    ips = [f"192.168.1.{i}" for i in range(1, 21)] + [f"10.0.0.{i}" for i in range(1, 21)]

    event_type = random.choice(event_types)
    source_ip = random.choice(ips)

    if event_type == 'login':
        status = random.choices(['success', 'failed'], weights=[0.7, 0.3])[0]
        details = f"Login {status} from {source_ip}"
    elif event_type == 'access':
        status = random.choices(['success', 'denied'], weights=[0.8, 0.2])[0]
        details = f"Access to {random.choice(resources)} - {status}"
    else:
        status = 'success'
        details = f"Privilege change: {random.choice(['elevated', 'revoked', 'updated'])}"

    return {
        'timestamp': timestamp,
        'event_type': event_type,
        'source_ip': source_ip,
        'user_id': user_id,
        'status': status,
        'details': details
    }

def generate_events(num_events, user_id, start_date, end_date):
    events = []
    time_range = (end_date - start_date).total_seconds()

    for _ in range(num_events):
        timestamp = start_date + timedelta(seconds=random.randint(0, int(time_range)))
        events.append(create_event(timestamp, user_id))

    return sorted(events, key=lambda x: x['timestamp'])


def insert_events(client, events):
    df = pd.DataFrame(events)
    batch_size = CONFIG['batch_size']

    for i in range(0, len(df), batch_size):
        batch = df.iloc[i:i + batch_size]
        client.execute(
            f'INSERT INTO {CONFIG["table_name"]} VALUES',
            batch.to_dict('records')
        )


# ==================== HÀM MAIN ====================
def main():
    print("Создание пользователей превышает пороговое значение 3 сигма...")

    client = get_clickhouse_client()

    # Tính ngưỡng
    mean, std, threshold = calculate_threshold(client)
    num_events = int(threshold * CONFIG['outlier_factor'])

    # Lấy time range và tạo events
    start, end = get_time_range(client)
    events = generate_events(num_events, CONFIG['outlier_user_id'], start, end)

    # Insert
    insert_events(client, events)


if __name__ == "__main__":
    main()