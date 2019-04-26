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
            return c.execute(query)
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
    count_standard = execute_query(con, count_rows_standard).fetchall()[0][0]
    if count_standard == 0:
        execute_query(con, test_data_standard)
        print("Standard Table data entered into empty database.")

    count_result = execute_query(con, count_rows_result).fetchall()[0][0]
    if count_result == 0:
        execute_query(con, test_data_result)
        print("Standard Table data entered into empty database.")

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

    for standard in entries:
        if standard[1] == "E":
            e_total += standard[0]
        elif standard[1] == "M":
            m_total += standard[0]
        elif standard[1] == "A":
            a_total += standard[0]

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
    return [name, total, e_total, m_total, a_total, left]


def credits_numbers():
    all_credits = get_credits("All", get_credits_all_query)
    l3_credits = get_credits("Level 3", get_credits_l3_query)
    l2_credits = get_credits("Level 2", get_credits_12_query)
    l1_credits = get_credits("Level 1", get_credits_l1_query)

    all_credits.append('all')
    l3_credits.append('l3')
    l2_credits.append('l2')
    l1_credits.append('l1')

    return [all_credits, l3_credits, l2_credits, l1_credits]


@app.route('/')
def home():
    credits_package = credits_numbers()

    print("OUTPUT: All credits: ", credits_package)

    # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]
    return render_template("home.html", results=credits_package)


@app.route('/overview')
def overview():
    # LIST OF ALL COMPLETED STANDARDS
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(get_all_done_standards)
    standards = cur.fetchall()

    # LIST OF ALL CREDITS BY GRADE / LEVEL
    credits_package = credits_numbers()

    # LEVEL ENDORSEMENT ["level", To E Endorsement, To M Endorsement]
    endorsement_data = [["l3", 50-credits_package[1][2], 50-credits_package[1][3]-credits_package[1][2]],
                        ["l2", 50-credits_package[2][2], 50-credits_package[2][3]-credits_package[1][2]],
                        ["l1", 50-credits_package[3][2], 50-credits_package[3][3]-credits_package[1][2]]]

    for level in endorsement_data:
        if level[1] < 0:
            level[1] = 0
        if level[2] < 0:
            level[2] = 0

    # OTHER DATA
    other_data = [endorsement_data, ["literacy", "numeracy", "reading", "writing"]]

    return render_template("overview.html", standards=standards, results=credits_package, other=other_data)


@app.route('/add-achievement')
def add_credits():
    return render_template("enter_credits.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0')
