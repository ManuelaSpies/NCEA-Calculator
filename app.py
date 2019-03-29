from flask import Flask, render_template, request, redirect
import sqlite3
from sqlite3 import Error
from import_data import *

DATABASE_NAME = "credit.db"

app = Flask(__name__)


def create_connection(db_file):
    """create a connection to the sqlite db"""
    try:
        connection = sqlite3.connect(db_file)
        initialise_tables(connection)
        return connection
    except Error as e:
        print(e)

    print("STATUS: create_connection completed.")
    return None


def execute_query(con, query):
    """executes query into database."""
    if con is not None:
        try:
            c = con.cursor()
            c.execute(query)
        except Error as e:
            print(e)
    else:
        print("ERROR: No connection in execute_query().")

    print("STATUS: execute_query() completed.")


def initialise_tables(con):
    """creates tables and enters initial values."""
    # Creates Tables
    execute_query(con, create_table_standard)
    execute_query(con, create_table_result)

    # Auto inserts Values into Tables

    print("STATUS: initialise_tables() completed.")


def get_credits(name, query):
    """counts and sorts all existing credits by grade."""
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(query)
    entries = cur.fetchall()
    print("Entries: ", entries)
    for entry in entries:
        print(entry)

    e_total = 0
    m_total = 0
    a_total = 0
    n_total = 0

    for standard in entries:
        if standard[1] == "E":
            e_total += standard[0]
        elif standard[1] == "M":
            m_total += standard[0]
        elif standard[1] == "A":
            a_total += standard[0]
        elif standard[1] == "N":
            n_total += standard[0]

    if name == "Level 1":
        goal = 80
    elif name == "All":
        goal = 0
    else:
        goal = 60

    total = e_total + m_total + a_total
    if total < goal:
        left = goal - e_total - m_total - a_total
    else:
        left = 0

    print("STATUS: get_credits completed.")
    return [name, total, e_total, m_total, a_total, n_total, left]


def credits_numbers():
    all_credits = get_credits("All", get_credits_all_query)
    l3_credits = get_credits("Level 3", get_credits_l3_query)
    l2_credits = get_credits("Level 2", get_credits_12_query)
    l1_credits = get_credits("Level 1", get_credits_l1_query)

    return [all_credits, l3_credits, l2_credits, l1_credits]


@app.route('/')
def home():
    credits_package = credits_numbers()
    print("AUSGABE: All credits: ", credits_package)

    return render_template("home.html", results=credits_package)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
