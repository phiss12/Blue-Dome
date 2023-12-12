import pandas as pd
import sqlite3
from pathlib import Path

# Load the Excel file
excel_file_path = ['python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (G SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (OM SERIES, CW SERIES, D SERIES, WORK ZONE(G) SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (PS SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (R SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (S SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SC SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SG SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SR SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SW SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA_MUTCD & DESCRIPTION (W SERIES).xlsx']
for i in excel_file_path:

  
    # Load the Excel file
    df = pd.read_excel(i)
    
    # Forward fill NaN values to handle merged cells
    df = df.fillna(method='ffill')
    
    # Drop rows with all NaN values
    df = df.dropna(how='all')
    
    df = df.drop_duplicates(subset='INDEX')
    
    # Reset the index of the DataFrame
    df = df.reset_index(drop=True)
    
    # Write the cleaned data back to the Excel file
    df.to_excel(i, index=False)
    database_name = "user_database.db"
    conn = sqlite3.connect(database_name)
    
    # Get the table name from the Excel file name
    table_name = Path(i).stem
    
    # Write the data to the SQLite database
    df.to_sql(table_name, conn, if_exists='replace', index=False)

# Close the connection to the SQLite database
conn.close()


['python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (G SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (OM SERIES, CW SERIES, D SERIES, WORK ZONE(G) SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (PS SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (R SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (S SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SC SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SG SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SR SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA MUTCD & DESCRIPTION (SW SERIES).xlsx',
'python work/SIGN MUTCD & DESCRIPTION/CA_MUTCD & DESCRIPTION (W SERIES).xlsx']