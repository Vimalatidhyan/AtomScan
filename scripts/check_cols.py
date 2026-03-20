import sqlite3
c = sqlite3.connect('technieum.db')
cols = [r[1] for r in c.execute('PRAGMA table_info(scan_runs)').fetchall()]
print('Columns:', cols)
row = c.execute('SELECT * FROM scan_runs WHERE id=1').fetchone()
print('Row:', dict(zip(cols, row)))
c.close()
