from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from import_data import *
# from flask_bcrypt import Bcrypt

DATABASE_NAME = "credit.db"

app = Flask(__name__)

# bcrypt = Bcrypt(app)
app.secret_key = "コレは秘密다. Jingle bells Kuchen."


def is_logged_in():
    try:
        print(session['user_id'])
        return True
    except KeyError:
        print("Not logged in")
        return False


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
    execute_query(con, create_table_user)

    # Auto inserts Values into Tables
    count_standard = execute_query(con, count_rows_standard).fetchall()[0][0]

    if count_standard == 0:
        execute_query(con, test_data_standard)
        print("Standard Table data entered into empty database.")

    count_result = execute_query(con, count_rows_result).fetchall()[0][0]
    if count_result == 0:
        execute_query(con, test_data_result)
        print("Result Table data entered into empty database.")

    count_user = execute_query(con, count_rows_user).fetchall()[0][0]
    if count_user == 0:
        execute_query(con, test_data_user)
        print("User Table data entered into empty database.")

    print("STATUS: initialise_tables() completed.")


def get_credits(name, query):
    """counts and sorts all existing credits by grade."""
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(query)
    entries = cur.fetchall()

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


def get_categories(data, number):
    outcome = 0
    for standard in data:
        if standard[number] == "Yes":
            outcome += standard[0]

    return outcome


@app.route('/')
def home():
    if is_logged_in():
        credits_package = credits_numbers()

        print("OUTPUT: All credits: ", credits_package)

        # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]
        return render_template("home.html", results=credits_package, logged_in=is_logged_in(), session=session)
    else:
        return render_template("login.html")


@app.route('/contact')
def contact():
    return "Not yet here :P"


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

    # LIT, NUM, ...
    cur.execute(get_all_lit_num_things)
    lit_num_data = cur.fetchall()

    curriculum_stuff = [get_categories(lit_num_data, 1), get_categories(lit_num_data, 2), get_categories(lit_num_data, 3), get_categories(lit_num_data, 4)]

    return render_template("overview.html",
                           standards=standards, results=credits_package, endorsement=endorsement_data,
                           litnum=curriculum_stuff, logged_in=is_logged_in(), session=session)


@app.route('/new-achievement/<code>')
def load_add_credits(code):
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(get_all_standard_names)
    asnumbers = cur.fetchall()

    if code == "error":
        alert = "Warning! An error occured!"
    elif code == "standard-exists":
        alert = "Warning! This standard was already achieved!"
    elif code == "standard-missing":
        alert = "Warning! The standard doesn't exist. Something went very wrong."
    elif code == "success":
        alert = "Your entry was saved. You can find it on your Overview."
    elif code == "enter":
        alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"
    else:
        alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"

    return render_template("enter_credits.html", as_numbers=asnumbers, alert=alert,
                           logged_in=is_logged_in(), session=session)


@app.route('/add-credits', methods=['POST'])
def add_credits():
    entry_name = request.form['input_as']
    entry_grade = request.form['input_grade']
    user_id = session['user_id']

    print("USER INPUT: {}, {}, {}".format(entry_name, entry_grade, user_id))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_name,))

    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    cur.execute(count_rows_new_entry, (entry_name,))
    result_results = cur.fetchall()
    result_results = result_results[0][0]

    if result_standard < 1:  # AND CHECK IF IT EXISTS IN RESULT!!!
        print("ERROR: Some error with the standards on the tables.")
        return redirect('/new-achievement/standard missing')

    elif result_results >= 1:
        print("USER: Standard already entered.")
        return redirect('/new-achievement/standard-exists')

    else:
        con = create_connection(DATABASE_NAME)
        entry_data = (entry_name, entry_grade, user_id)

        cur = con.cursor()
        cur.execute(new_credit_entry_query, entry_data)

        con.commit()
        con.close()
        return redirect('/new-achievement/success')


@app.route('/new-standard/<code>')
def load_add_standard(code):
    if code == "enter":
        alert = "Enter a standard! :)"
    elif code == "input-as":
        alert = "Error! This AS Number already exists."
    elif code == "input=int":
        alert = "Error! An integer-only input was entered differently."
    elif code == "Success":
        alert = "Success! The standard was added and you can enter your grade now"
    else:
        alert = "Enter a standard! :)"
    return render_template("enter_standard.html", alert=alert, logged_in=is_logged_in(), session=session)


@app.route('/add-standard', methods=['POST'])
def add_standard():
    entry_as = request.form['standard_name']
    entry_desc = request.form['description']
    entry_cred = request.form['credits']
    entry_lev = request.form['ncea_level']
    entry_read = request.form['reading']
    entry_writ = request.form['writing']
    entry_lit = request.form['literacy']
    entry_num = request.form['numeracy']
    entry_ue = request.form['ue_credits']
    user_id = session['user_id']

    print("USER INPUT: {}, {}, {}, {}, {}, {}, {}, {}, {}, {}".format
          (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue, user_id))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_as,))

    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    if result_standard > 1:
        print("ERROR: AS Number exists already.")
        return redirect('/new-standard/input-as')

    else:
        addition_allowed = True
        try:
            entry_as = int(entry_as)
        except ValueError:
            print("ERROR: Integer input (AS number) is not written in integers.")
            addition_allowed = False

        try:
            entry_cred = int(entry_cred)
        except ValueError:
            print("ERROR: Integer input (credits) is not written in integers.")
            addition_allowed = False

        if addition_allowed:
            con = create_connection(DATABASE_NAME)
            entry_data = (entry_as, entry_desc, entry_cred, entry_lev, entry_read, entry_writ, entry_lit, entry_num, entry_ue, user_id)
            cur = con.cursor()
            cur.execute(new_standard_entry_query, entry_data)
            con.commit()
            con.close()
            return redirect('/new-standard/success')

        else:
            return redirect('/new-standard/input-int')


@app.route('/register')
def register():
    return "Jingle bells"


@app.route('/create-new-user', methods=['POST'])
def create_new_user():
    username = request.form['username']
    password1 = request.form['password1'].strip().capitalize()
    password2 = request.form['password2'].strip().capitalize()
    email = request.form['email'].strip()

    if password1 != password2:
        return redirect('/')

    if " " in username:
        return redirect('')

    # CHECK IF THE USERNAME IS ALREADY EXISTING.

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    con = create_connection(DATABASE_NAME)
    user = (username, hashed_password, email)
    cur = con.cursor()
    cur.execute(create_user, user)

    return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['login-username']
    password = request.form['login-password']

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_username, (username,))
    user_check = cur.fetchall()[0][0]

    if user_check != 1:
        redirect(request.referrer + "?error=username+invalid")

    user_data = cur.execute(find_user, (username,)).fetchall()

    try:
        user_id = user_data[0][0]
        username = user_data[0][1]
        db_password = user_data[0][2]
    except IndexError:
        return redirect(request.referrer + "?error=Username+invalid+or+password+incorrect")

    # if not bcrypt.check_password_hash(db_password, password):
    #     return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

    if db_password != password:
        return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

    session['user_id'] = user_id
    session['username'] = username
    return redirect(request.referrer)


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/')


@app.route('/settings')
def settings_page():
    if is_logged_in():
        print("DO STUFF")
    else:
        return render_template("register.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0')