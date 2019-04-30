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
        print("Result Table data entered into empty database.")

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

    print("STATUS: get_credits completed for {}.".format(name))
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


@app.route('/new-achievement/<error>')
def load_add_credits(error):
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(get_all_standard_names)
    asnumbers = cur.fetchall()
    print(asnumbers)

    if error == "error":
        alert = "Warning! You chose a standard that already has been entered!"
    elif error == "success":
        alert = "Your entry was saved. You can find it on your Overview."
    elif error == "enter":
        alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"
    else:
        alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"

    return render_template("enter_credits.html", as_numbers=asnumbers, alert=alert)


@app.route('/add-credits', methods=['POST'])
def add_credits():
    entry_name = request.form['input_as']
    entry_grade = request.form['input_grade']
    print("USER INPUT: {}, {}".format(entry_name, entry_grade))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_name,))
    result = cur.fetchall()
    result = result[0][0]
    print("RESULT: {}".format(result))

    if result < 1:
        print("ERROR: The outcome of the result != 1 test is not 1.")
        return redirect('/new-achievement/error')

    else:
        con = create_connection(DATABASE_NAME)
        entry_data = (entry_name, entry_grade)
        cur = con.cursor()
        cur.execute(new_credit_entry_query, entry_data)
        con.commit()
        con.close()
        return redirect('/new-achievement/success')


@app.route('/enter-standard')
def add_standard():
    return render_template("enter_standard.html")


@app.route('/contact')
def contact():
    return "Not yet here :P"


if __name__ == "__main__":
    app.run(host='0.0.0.0')
