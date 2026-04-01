import sqlite3
conn = sqlite3.connect('technieum.db')
c = conn.cursor()
c.execute("SELECT id, message FROM scan_events WHERE level='warning' OR message LIKE '%WARN%'")
rows = c.fetchall()
to_del = [r[0] for r in rows if 'S3Scanner' in str(r[1]) or 'asnmap' in str(r[1]) or '/mnt/' in str(r[1])]
for i in to_del: c.execute('DELETE FROM scan_events WHERE id=?', (i,))
conn.commit()
print(f'Deleted {len(to_del)} warning records')
