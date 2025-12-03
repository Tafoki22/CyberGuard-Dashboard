# modules/analytics.py
from datetime import datetime, timedelta
from sqlalchemy import func
from database.db_session import create_session
from database.models import ScanResult, BreachAlert

def get_activity_data_last_7_days():
    """
    Queries the SQLite DB for real activity counts over the last 7 days.
    Returns: (dates_list, counts_list)
    """
    session = create_session()
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=6)
    
    # Initialize dictionary with 0s for the last 7 days
    data_map = {}
    for i in range(7):
        day = (start_date + timedelta(days=i)).strftime('%d-%b')
        data_map[day] = 0

    # 1. Query Network Scans
    scans = session.query(ScanResult.timestamp).filter(ScanResult.timestamp >= start_date).all()
    for s in scans:
        day = s.timestamp.strftime('%d-%b')
        if day in data_map:
            data_map[day] += 1

    # 2. Query Breach Alerts
    breaches = session.query(BreachAlert.timestamp).filter(BreachAlert.timestamp >= start_date).all()
    for b in breaches:
        day = b.timestamp.strftime('%d-%b')
        if day in data_map:
            data_map[day] += 1

    session.close()

    # Convert to lists for Matplotlib
    dates = list(data_map.keys())
    counts = list(data_map.values())
    
    return dates, counts

def get_security_posture_score():
    """
    Calculates a 'Security Health Score' based on recent findings.
    """
    session = create_session()
    
    # Count High Risks
    high_risks = session.query(ScanResult).filter(ScanResult.risk_level.like('%High%')).count()
    breaches = session.query(BreachAlert).count()
    
    base_score = 100
    base_score -= (high_risks * 5)
    base_score -= (breaches * 10)
    
    if base_score < 0: base_score = 0
    
    status = "SECURE"
    color = "green"
    if base_score < 50:
        status = "CRITICAL"
        color = "red"
    elif base_score < 80:
        status = "WARNING"
        color = "orange"
        
    session.close()
    return base_score, status, color