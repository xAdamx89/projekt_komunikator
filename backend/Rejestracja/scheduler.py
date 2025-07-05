from apscheduler.schedulers.background import BackgroundScheduler
import time
from db import db

def update_user_activity():
    print(f'Wykonuje sprawdzenie aktywności... {time.process_time()}')
    db.query("""
        DELETE FROM users_token
        WHERE expires_at < NOW();
    """)

if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_user_activity, 'interval', minutes=1)
    scheduler.start()

    try:
        #czas = 2
        while True:
            time.sleep(2)
            #print(f'czas {czas}')
            #czas = czas + 2
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()