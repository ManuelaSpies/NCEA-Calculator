from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from import_data import *
# from flask_bcrypt import Bcrypt

DATABASE_NAME = "credit.db"

app = Flask(__name__)

# bcrypt = Bcrypt(app)

app.secret_key = "コレは秘密다. Jingle bells Käsekuchen. 4729371927"


def is_logged_in():
    # initialise_tables(create_connection(DATABASE_NAME))

    try:
        print("Session:", session['username'])
        return session['user_id'] != ""
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
    execute_query(con, create_table_user)
    execute_query(con, create_table_standard)
    execute_query(con, create_table_result)

    print("STATUS: initialise_tables() completed.")


def get_credits(name, query):
    """counts and sorts all existing credits by grade."""
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(query, (session['user_id'],))
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
def main():
    if is_logged_in():
        credits_package = credits_numbers()
        # Credit's Package: [[all [name, total, e, m, a, left, codename (all/l3/...)], l3, l2, l1]
        return render_template("home.html", results=credits_package, logged_in=is_logged_in(), session=session)

    else:
        return redirect('/login/user')


@app.route('/login/<message>')
def login_page(message):
    if message == "user":
        message = False
        colour = "alert-light"
    elif message == "account":
        message = "Something is wrong with your account. Please contact the server operator."
        colour = "alert-danger"
    elif message == "incorrect":
        message = "The username or password is incorrect."
        colour = "alert-warning"
    else:
        message = False
        colour = "alert-light"
    return render_template("login.html", message=message, colour=colour)


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/overview')
def overview():
    if not is_logged_in():
        return redirect('/login/account')

    # LIST OF ALL COMPLETED STANDARDS
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    cur.execute(get_all_done_standards, (session['user_id'],))
    standards = cur.fetchall()

    # LIST OF ALL CREDITS BY GRADE / LEVEL
    credits_package = credits_numbers()

    # LEVEL ENDORSEMENT ["level", To E Endorsement, To M Endorsement]
    endorsement_data = [["l3", 50-credits_package[1][2], 50-credits_package[1][3]-credits_package[1][2]],
                        ["l2", 50-credits_package[2][2], 50-credits_package[2][3]-credits_package[2][2]],
                        ["l1", 50-credits_package[3][2], 50-credits_package[3][3]-credits_package[3][2]]]

    for level in endorsement_data:
        if level[1] < 0:
            level[1] = 0
        if level[2] < 0:
            level[2] = 0

    # LIT, NUM, ...
    cur.execute(get_all_lit_num_things, (session['user_id'],))
    lit_num_data = cur.fetchall()

    curriculum_stuff = [get_categories(lit_num_data, 1), get_categories(lit_num_data, 2), get_categories(lit_num_data, 3), get_categories(lit_num_data, 4)]

    return render_template("overview.html",
                           standards=standards, results=credits_package, endorsement=endorsement_data,
                           litnum=curriculum_stuff, logged_in=is_logged_in(), session=session)


@app.route('/new-achievement/<code>')
def load_add_credits(code):
    if not is_logged_in():
        return redirect('/login/account')

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    standards_exist = cur.execute(count_rows_standard_user, (session['user_id'],)).fetchall()[0][0] > 0

    if standards_exist:
        cur.execute(get_all_standard_names, (session['user_id'],))
        asnumbers = cur.fetchall()

        if code == "error":
            alert = "Warning! An error occured!"
            colour = "alert-danger"
        elif code == "standard-exists":
            alert = "Error! This standard was already achieved! Nothing was processed."
            colour = "alert-warning"
        elif code == "standard-missing":
            alert = "Warning! The standard doesn't exist. Did you enter it?"
            colour = "alert-warning"
        elif code == "success":
            alert = "Your entry was saved. You can find it on your Overview."
            colour = "alert-success"
        elif code == "enter":
            alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"
            colour = "alert-light"
        else:
            alert = "Please remember that if your standard doesn't show up here, you'll need to enter it first!"
            colour = "alert-light"

        return render_template("enter_credits.html", as_numbers=asnumbers, alert=alert,
                               logged_in=is_logged_in(), session=session, colour=colour)
    else:
        print("ERROR: User has no standards; redirected towards enter standards page.")
        return redirect('/new-standard/no-standards')


@app.route('/add-credits', methods=['POST'])
def add_credits():
    if not is_logged_in():
        return redirect('/login/account')

    entry_name = request.form['input_as']
    entry_grade = request.form['input_grade']
    user_id = session['user_id']

    print("USER INPUT: {}, {}, {}".format(entry_name, entry_grade, user_id))

    # Check if input valid.
    con = create_connection(DATABASE_NAME)
    cur = con.cursor()
    cur.execute(count_rows_credit_entry, (entry_name, user_id,))

    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    cur.execute(count_rows_new_entry, (entry_name, user_id))
    result_results = cur.fetchall()
    result_results = result_results[0][0]

    if result_standard < 1:
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
    if not is_logged_in():
        return redirect('/login/account')

    if code == "enter":
        alert = "Enter a standard! :)"
        colour = "alert-light"
    elif code == "input-as":
        alert = "Error! This AS Number already exists. Nothing was processed."
        colour = "alert-warning"
    elif code == "input-int":
        alert = "Error! An integer-only input was entered in another form. Nothing was processed."
        colour = "alert-danger"
    elif code == "success":
        alert = "Success! The standard was added and you can enter your grade now!"
        colour = "alert-success"
    elif code == "no-standard":
        alert = "Error! You don't have any standards. Enter them first before adding your credits."
        colour = "alert-warning"
    else:
        alert = "Enter a standard! :)"
    return render_template("enter_standard.html", alert=alert, logged_in=is_logged_in(), session=session, colour=colour)


@app.route('/add-standard', methods=['POST'])
def add_standard():
    if not is_logged_in():
        return redirect('/login/account')

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
    cur.execute(count_rows_credit_entry, (entry_as, user_id, ))

    result_standard = cur.fetchall()
    result_standard = result_standard[0][0]

    if result_standard > 0:
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
            print('STATEMENT: Input added successfully.')
            return redirect('/new-standard/success')

        else:
            return redirect('/new-standard/input-int')


@app.route('/register/<error>')
def register(error):
    if error == "new":
        message = False
        colour = "alert-light"
    elif error == "password":
        message = "Your passwords aren't matching."
        colour = "alert-warning"
    elif error == "space":
        message = "There is a space in your username!"
        colour = "alert-warning"
    elif error == "username":
        message = "This username is already taken. Try another one."
        colour = "alert-danger"
    else:
        message = "Something went wrong. Contact the site administrator if this problem remains."
        colour = "alert-danger"

    return render_template("register.html", error_message=message, logged_in=is_logged_in(), session=session, colour=colour)


@app.route('/create-new-user', methods=['POST'])
def create_new_user():
    username = request.form['username']
    password1 = request.form['password1'].strip().capitalize()
    password2 = request.form['password2'].strip().capitalize()

    if password1 != password2:
        return redirect('register/password')

    if " " in username:
        return redirect('/register/space')

    # hashed_password = bcrypt.generate_password_hash(password1).decode('utf-8')
    hashed_password = password1
    new_user = (username, hashed_password)

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    # Catches user name already exists errors.
    try:
        cur.execute(create_user, new_user)
    except sqlite3.IntegrityError:
        return redirect('/register/username')

    con.commit()
    con.close()

    con = create_connection(DATABASE_NAME)
    cur = con.cursor()

    user_data = cur.execute(find_user, (username,)).fetchall()[0]
    print("NEW USER: {}".format(user_data))

    user_id = user_data[0]
    session['user_id'] = user_id
    session['username'] = username
    print(user_id)

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
        redirect('/login/account')

    user_data = cur.execute(find_user, (username,)).fetchall()

    try:
        user_id = user_data[0][0]
        username = user_data[0][1]
        db_password = user_data[0][2]
    except IndexError:
        return redirect('/login/account')

    # if not bcrypt.check_password_hash(db_password, password):
    #     return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

    if db_password != password:
        return redirect('/login/incorrect')

    session['user_id'] = user_id
    session['username'] = username
    return redirect('/')


@app.route('/logout')
def logout():
    if not is_logged_in():
        return redirect('/login/user')

    print("LOGGING OUT.")
    # print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    # print(list(session.keys()))
    return redirect('/')


@app.route('/settings')
def settings_page():
    if is_logged_in():
        return "This page does not yet exist. How did you get here?"
    else:
        return render_template("register.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0')