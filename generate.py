import random
from datetime import datetime, timedelta
from clickhouse_driver import Client
import pandas as pd
from typing import List, Dict, Any, Tuple

# ==================== CẤU HÌNH ====================
CONFIG = {
    'clickhouse_host': 'localhost',
    'clickhouse_port': 9000,
    'database': 'default',
    'clickhouse_user': 'myuser',
    'clickhouse_password': 'mypassword',
    'table_name': 'security_events',
    'total_events': 100000,
    'days_range': 90,  # 3 months
    'user_range': (1001, 1100),  # 100 users
    'event_weights': [0.4, 0.4, 0.2],  # login, access, privilege_change
    'brute_force_ratio': 0.15,  # 15% events is brute-force
    'brute_force_ips': ['203.0.113.42', '203.0.113.100', '10.0.0.99']
}

def get_clickhouse_client() -> Client:
    return Client(
        host=CONFIG['clickhouse_host'],
        port=CONFIG['clickhouse_port'],
        database=CONFIG['database'],
        user=CONFIG['clickhouse_user'],
        password=CONFIG['clickhouse_password']
    )

def create_table(client: Client) -> None:
    create_table_query = """
     CREATE TABLE IF NOT EXISTS security_events (
        timestamp    DateTime,
        event_type   String, 
        source_ip     String,
        user_id       UInt32,
        status        String,
        details        String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (event_type, source_ip, timestamp);
     """
    client.execute(create_table_query)

def define_data_templates() -> Dict:
    # Định nghĩa status cho từng event type
    statuses = {
        'login': ['success', 'failed'],
        'access': ['success', 'denied'],
        'privilege_change': ['success']
    }

    # IP prefixes
    ip_prefixes = ['192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.']
    # Tạo danh sách IP bình thường
    normal_ips = [f"{random.choice(ip_prefixes)}{random.randint(1, 254)}" for _ in range(50)]
    # Resources cho access events
    resources = ['/api/data', '/admin', '/dashboard', '/reports', '/settings']
    # Privilege changes
    privilege_changes = ['elevated to admin', 'revoked access', 'added to group', 'permission update']

    return {
        'statuses': statuses,
        'brute_force_ips': CONFIG['brute_force_ips'],
        'normal_ips': normal_ips,
        'resources': resources,
        'privilege_changes': privilege_changes
    }

def generate_timestamp_range() -> Tuple[datetime, datetime]:
    end_date = datetime.now()
    start_date = end_date - timedelta(days=CONFIG['days_range'])
    return start_date, end_date

def random_timestamp(start_date: datetime, end_date: datetime) -> datetime:
    time_between = end_date - start_date
    random_seconds = random.randint(0, int(time_between.total_seconds()))
    return start_date + timedelta(seconds=random_seconds)


def generate_brute_force_batch(ip: str,
                                start_time: datetime,
                                num_attempts: int,
                                user_ids: List[int],
                                templates: Dict) -> List[Dict[str, Any]]:
    events = []
    time_spread = 300

    for i in range(num_attempts):
        if i == 0:
            attempt_time = start_time
        else:
            seconds_between = random.uniform(0.5, 15)
            attempt_time = events[-1]['timestamp'] + timedelta(seconds=seconds_between)

        if (attempt_time - start_time).total_seconds() > time_spread:
            break

        user_id = random.choice(user_ids + [9999, 10000, 10001])

        if i < num_attempts - 1 or random.random() > 0.05:
            status = 'failed'
            details = f"Failed login attempt from {ip} for user {user_id} - brute force attempt #{i + 1}"
        else:
            status = 'success'
            details = f"Successful login from {ip} for user {user_id} after {i} failed attempts"

        events.append({
            'timestamp': attempt_time,
            'event_type': 'login',
            'source_ip': ip,
            'user_id': user_id,
            'status': status,
            'details': details
        })

    return events


def select_source_ip(event_type: str, status: str, templates: Dict) -> str:
    if event_type == 'login' and status == 'failed':
        # 30% failed login là từ brute-force IPs
        if random.random() < 0.3:
            return random.choice(templates['brute_force_ips'])

    return random.choice(templates['normal_ips'] + templates['brute_force_ips'])


def generate_user_ids() -> List[int]:
    start, end = CONFIG['user_range']
    return list(range(start, end + 1))

def select_user_id(event_type: str,
                    status: str,
                    source_ip: str,
                    user_ids: List[int],
                    templates: Dict) -> int:
    if (event_type == 'login' and
            status == 'failed' and
            source_ip in templates['brute_force_ips']):
        # Brute-force thử nhiều user IDs khác nhau
        return random.choice(user_ids + [9999])  # Thêm user không tồn tại

    return random.choice(user_ids)


def generate_details(event_type: str,
                    status: str,
                    source_ip: str,
                    user_id: int,
                    templates: Dict) -> str:
    if event_type == 'login':
        if source_ip in templates['brute_force_ips'] and status == 'failed':
            return f"Brute force attempt from {source_ip} for user {user_id}"
        else:
            return f"Login attempt from {source_ip} for user {user_id} - {status}"

    elif event_type == 'access':
        resource = random.choice(templates['resources'])
        access_status = 'granted' if status == 'success' else 'blocked'
        return f"Access to {resource} - {access_status}"

    else:  # privilege_change
        return f"Privilege change: {random.choice(templates['privilege_changes'])} for user {user_id}"

def generate_single_event(start_date: datetime,
                            end_date: datetime,
                            user_ids: List[int],
                            templates: Dict) -> Dict[str, Any]:
    event_types = ['login', 'access', 'privilege_change']
    event_type = random.choices(event_types, weights=CONFIG['event_weights'])[0]
    status = random.choice(templates['statuses'][event_type])
    source_ip = select_source_ip(event_type, status, templates)
    timestamp = random_timestamp(start_date, end_date)
    user_id = select_user_id(event_type, status, source_ip, user_ids, templates)
    details = generate_details(event_type, status, source_ip, user_id, templates)

    return {
        'timestamp': timestamp,
        'event_type': event_type,
        'source_ip': source_ip,
        'user_id': user_id,
        'status': status,
        'details': details
    }

def generate_events_batch(num_events: int,
                            start_date: datetime,
                            end_date: datetime,
                            user_ids: List[int],
                            templates: Dict) -> List[Dict[str, Any]]:
    events = []

    # Tính số lượng brute-force events
    num_brute_force = int(num_events * CONFIG['brute_force_ratio'])
    num_normal = num_events - num_brute_force

    brute_force_events = []
    remaining_bruteforce = num_brute_force
    num_bf_sessions = random.randint(8, 15)

    for session in range(num_bf_sessions):
        if remaining_bruteforce <= 0:
            break
        bf_ip = random.choice(templates['brute_force_ips'])
        session_start = random_timestamp(start_date, end_date)

        session_attempts = min(
            random.randint(20, 200),
            remaining_bruteforce
        )

        bf_batch = generate_brute_force_batch(
            bf_ip,
            session_start,
            session_attempts,
            user_ids,
            templates
        )

        brute_force_events.extend(bf_batch)
        remaining_bruteforce -= len(bf_batch)

    if remaining_bruteforce > 0:
        for i in range(remaining_bruteforce):
            bf_ip = random.choice(templates['brute_force_ips'])
            timestamp = random_timestamp(start_date, end_date)
            user_id = random.choice(user_ids + [9999])

            brute_force_events.append({
                'timestamp': timestamp,
                'event_type': 'login',
                'source_ip': bf_ip,
                'user_id': user_id,
                'status': 'failed',
                'details': f"Brute force attempt from {bf_ip} for user {user_id}"
            })

    for i in range(num_normal):
        event = generate_single_event(start_date, end_date, user_ids, templates)
        events.append(event)

    all_events = events + brute_force_events
    random.shuffle(all_events)
    all_events.sort(key=lambda x: x['timestamp'])

    return all_events

def insert_events(client: Client, events: List[Dict[str, Any]]) -> None:
    df = pd.DataFrame(events)

    batch_size = 10000
    for i in range(0, len(df), batch_size):
        batch = df.iloc[i:i + batch_size]
        client.execute(
            f'INSERT INTO {CONFIG["table_name"]} (timestamp, event_type, source_ip, user_id, status, details) VALUES',
            batch.to_dict('records')
        )

def verify_data(client: Client) -> None:

    # Đếm tổng số records
    result = client.execute(f"SELECT COUNT(*) FROM {CONFIG['table_name']}")
    total = result[0][0]
    print(f"\nОбщее количество записей в таблице: {total}")

    # Thống kê theo event_type
    stats = client.execute(f"""
        SELECT 
            event_type, 
            COUNT(*) as count,
            COUNT(DISTINCT source_ip) as unique_ips
        FROM {CONFIG['table_name']} 
        GROUP BY event_type
    """)

    print("\nСтатистика по типу события:")
    for row in stats:
        print(f"  - {row[0]}: {row[1]} events (с {row[2]} IPs)")

    # Hiển thị mẫu
    print("\n5-строчная запись образца:")
    sample = client.execute(f"SELECT * FROM {CONFIG['table_name']} LIMIT 5")
    for i, row in enumerate(sample, 1):
        print(f"  {i}. {row}")


def main():
    try:
        # Bước 1: Kết nối ClickHouse
        client = get_clickhouse_client()

        # Bước 2: Tạo bảng
        create_table(client)

        # Bước 3: Chuẩn bị dữ liệu
        templates = define_data_templates()
        user_ids = generate_user_ids()
        start_date, end_date = generate_timestamp_range()

        # Bước 4: Tạo events
        events = generate_events_batch(
            CONFIG['total_events'],
            start_date,
            end_date,
            user_ids,
            templates
        )

        # Bước 5: Insert dữ liệu
        insert_events(client, events)

        # Bước 6: Kiểm tra
        verify_data(client)
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        raise

if __name__ == "__main__":
    main()