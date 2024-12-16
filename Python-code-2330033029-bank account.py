import re
import sqlite3
from datetime import datetime, timedelta
import hashlib
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import logging
import threading
import schedule
import time

# ========== Logging Configuration ==========
logging.basicConfig(
    filename='banking_system.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

# ========== Database Initialization and Management ==========
class DatabaseManager:
    def __init__(self, db_name="banking.db"):
        try:
            self.conn = sqlite3.connect(db_name, check_same_thread=False)
            self.create_tables()
            self.create_indexes()
            logging.info("Database connected and initialized.")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")

    def create_tables(self):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    name TEXT NOT NULL,
                                    email TEXT NOT NULL UNIQUE,
                                    password_hash TEXT NOT NULL,
                                    phone TEXT,
                                    daily_limit REAL DEFAULT 0,
                                    total_deposits REAL DEFAULT 0,
                                    loan_total REAL DEFAULT 0,
                                    balance REAL DEFAULT 0,
                                    last_interest_update_time TEXT
                                  )''')

                cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (
                                    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    amount REAL,
                                    transaction_type TEXT,
                                    timestamp TEXT,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')

                cursor.execute('''CREATE TABLE IF NOT EXISTS debts (
                                    debt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    debt_name TEXT,
                                    amount REAL,
                                    annual_rate REAL,
                                    years INTEGER,
                                    due_date TEXT,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')

                # Table for recording daily interest
                cursor.execute('''CREATE TABLE IF NOT EXISTS daily_interest (
                                    interest_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    date TEXT,
                                    interest_amount REAL,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')

                cursor.execute('''CREATE TABLE IF NOT EXISTS budgets (
                                    budget_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    category TEXT,
                                    amount REAL,
                                    created_at TEXT,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')
            logging.info("Tables created or verified successfully.")
        except sqlite3.Error as e:
            logging.error(f"Failed to create tables: {e}")

    def create_indexes(self):
        try:
            with self.conn:
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_debts_user ON debts(user_id);")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_daily_interest_user ON daily_interest(user_id);")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id);")
            logging.info("Indexes created or verified successfully.")
        except sqlite3.Error as e:
            logging.error(f"Failed to create index: {e}")

    def add_user(self, name, email, password_hash, phone, daily_limit=0, total_deposits=0, loan_total=0, balance=0):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""INSERT INTO users (name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance, last_interest_update_time) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                               (name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance, datetime.now().isoformat()))
                user_id = cursor.lastrowid
                logging.info(f"User '{name}' added with ID {user_id}.")
                return user_id
        except sqlite3.IntegrityError:
            logging.warning(f"Attempt to register with existing email: {email}.")
            return None
        except sqlite3.Error as e:
            logging.error(f"Failed to add user: {e}")
            return None

    def get_user_by_email(self, email):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            logging.info(f"Fetched user by email: {email}.")
            return user
        except sqlite3.Error as e:
            logging.error(f"Failed to query user by email: {e}")
            return None

    def get_user_by_id(self, user_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            user = cursor.fetchone()
            logging.info(f"Fetched user by ID: {user_id}.")
            return user
        except sqlite3.Error as e:
            logging.error(f"Failed to query user by ID: {e}")
            return None

    def update_user_balance(self, user_id, new_balance):
        try:
            with self.conn:
                self.conn.execute("UPDATE users SET balance = ? WHERE user_id = ?", (new_balance, user_id))
                logging.info(f"Updated balance for user ID {user_id} to {new_balance}.")
        except sqlite3.Error as e:
            logging.error(f"Failed to update user balance: {e}")

    def update_user_info(self, user_id, **kwargs):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                for key, value in kwargs.items():
                    if value is not None:
                        cursor.execute(f"UPDATE users SET {key} = ? WHERE user_id = ?", (value, user_id))
                        logging.info(f"Updated '{key}' for user ID {user_id} to {value}.")
        except sqlite3.Error as e:
            logging.error(f"Failed to update user information: {e}")

    def record_transaction(self, user_id, amount, transaction_type):
        try:
            with self.conn:
                timestamp = datetime.now().isoformat()
                self.conn.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                     VALUES (?, ?, ?, ?)""",
                                  (user_id, amount, transaction_type, timestamp))
                logging.info(f"Recorded transaction for user ID {user_id}: {transaction_type} of amount {amount}.")
        except sqlite3.Error as e:
            logging.error(f"Failed to record transaction: {e}")

    def get_transactions(self, user_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp", (user_id,))
            transactions = cursor.fetchall()
            logging.info(f"Fetched transactions for user ID {user_id}.")
            return transactions
        except sqlite3.Error as e:
            logging.error(f"Failed to query transactions: {e}")
            return []

    def add_debt(self, user_id, debt_name, amount, annual_rate, years, due_date):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""INSERT INTO debts (user_id, debt_name, amount, annual_rate, years, due_date) 
                                  VALUES (?, ?, ?, ?, ?, ?)""",
                               (user_id, debt_name, amount, annual_rate, years, due_date))
                debt_id = cursor.lastrowid
                cursor.execute("UPDATE users SET loan_total = loan_total + ? WHERE user_id = ?", (amount, user_id))
                cursor.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, amount, "debt_addition", datetime.now().isoformat()))
                logging.info(f"Added debt '{debt_name}' for user ID {user_id} with ID {debt_id}.")
                return debt_id
        except sqlite3.Error as e:
            logging.error(f"Failed to add debt: {e}")
            return None

    def get_debts(self, user_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM debts WHERE user_id = ?", (user_id,))
            debts = cursor.fetchall()
            logging.info(f"Fetched debts for user ID {user_id}.")
            return debts
        except sqlite3.Error as e:
            logging.error(f"Failed to query debts: {e}")
            return []

    def pay_debt(self, user_id, debt_id, amount):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("SELECT amount FROM debts WHERE debt_id = ? AND user_id = ?", (debt_id, user_id))
                result = cursor.fetchone()
                if not result:
                    logging.warning(f"Debt ID {debt_id} not found for user ID {user_id}.")
                    raise ValueError("Debt not found.")
                current_amount = result[0]
                if amount <= 0:
                    logging.warning(f"Invalid payment amount: {amount}.")
                    raise ValueError("Payment amount must be positive.")
                if amount > current_amount:
                    logging.warning(f"Payment amount {amount} exceeds debt amount {current_amount}.")
                    raise ValueError("Payment exceeds debt amount.")
                new_amount = current_amount - amount
                if new_amount == 0:
                    cursor.execute("DELETE FROM debts WHERE debt_id = ?", (debt_id,))
                    logging.info(f"Debt ID {debt_id} fully paid and removed.")
                else:
                    cursor.execute("UPDATE debts SET amount = ? WHERE debt_id = ?", (new_amount, debt_id))
                    logging.info(f"Debt ID {debt_id} updated to new amount {new_amount}.")
                cursor.execute("UPDATE users SET loan_total = loan_total - ? WHERE user_id = ?", (amount, user_id))
                cursor.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, -amount, "debt_payment", datetime.now().isoformat()))
                logging.info(f"Recorded debt payment of {amount} for user ID {user_id}.")
        except sqlite3.Error as e:
            logging.error(f"Failed to pay debt: {e}")
            raise
        except ValueError as ve:
            logging.warning(f"Debt payment error: {ve}")
            raise

    def set_budget(self, user_id, category, amount):
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""INSERT INTO budgets (user_id, category, amount, created_at) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, category, amount, datetime.now().isoformat()))
                logging.info(f"Set budget for category '{category}' with amount {amount} for user ID {user_id}.")
        except sqlite3.Error as e:
            logging.error(f"Failed to set budget: {e}")

    def get_budgets(self, user_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM budgets WHERE user_id = ?", (user_id,))
            budgets = cursor.fetchall()
            logging.info(f"Fetched budgets for user ID {user_id}.")
            return budgets
        except sqlite3.Error as e:
            logging.error(f"Failed to get budget records: {e}")
            return []

    def get_all_users(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            logging.info("Fetched all users for interest update.")
            return users
        except sqlite3.Error as e:
            logging.error(f"Failed to query all users: {e}")
            return []

    def update_all_users_interest(self):
        annual_rate = 0.02
        daily_rate = annual_rate / 365

        try:
            with self.conn:
                self.conn.execute('BEGIN')
                all_users = self.get_all_users()
                for user_data in all_users:
                    user_id = user_data[0]
                    balance = user_data[8]
                    last_interest_update_time = user_data[9]

                    # 如果没有上次计息时间，则不计算本次利息，只设定基准点
                    if not last_interest_update_time:
                        self.update_user_info(user_id, last_interest_update_time=datetime.now().isoformat())
                        continue

                    last_update_time = datetime.fromisoformat(last_interest_update_time)
                    now = datetime.now()
                    delta_days = (now.date() - last_update_time.date()).days
                    if delta_days <= 0:
                        continue

                    all_transactions = self.get_transactions(user_id)
                    filtered_transactions = [t for t in all_transactions if datetime.fromisoformat(t[4]) > last_update_time]

                    daily_transactions = {}
                    for tx in filtered_transactions:
                        tx_date = datetime.fromisoformat(tx[4]).date()
                        daily_transactions.setdefault(tx_date, 0)
                        daily_transactions[tx_date] += tx[2]

                    current_date = last_update_time.date()
                    current_balance = balance
                    cursor = self.conn.cursor()

                    while current_date < now.date():
                        current_date += timedelta(days=1)
                        if current_date in daily_transactions:
                            current_balance += daily_transactions[current_date]
                        previous_balance = current_balance
                        current_balance *= (1 + daily_rate)
                        interest_gained = current_balance - previous_balance

                        cursor.execute("INSERT INTO daily_interest (user_id, date, interest_amount) VALUES (?, ?, ?)",
                                       (user_id, current_date.isoformat(), interest_gained))
                        logging.info(f"Applied interest for user ID {user_id} on {current_date}: {interest_gained:.2f}")

                    self.update_user_balance(user_id, current_balance)
                    self.update_user_info(user_id, last_interest_update_time=now.isoformat())

                self.conn.commit()
                logging.info("All users' interest updated successfully.")
        except Exception as e:
            self.conn.rollback()
            logging.error(f"Failed to update all users' interest: {e}")

    def get_daily_interest_records(self, user_id, days=7):
        try:
            cursor = self.conn.cursor()
            start_date = (datetime.now().date() - timedelta(days=days)).isoformat()
            cursor.execute("SELECT date, interest_amount FROM daily_interest WHERE user_id = ? AND date >= ? ORDER BY date",
                           (user_id, start_date))
            records = cursor.fetchall()
            logging.info(f"Fetched daily interest records for user ID {user_id} for the last {days} days.")
            return records
        except sqlite3.Error as e:
            logging.error(f"Failed to get daily interest records: {e}")
            return []

    def close(self):
        try:
            self.conn.close()
            logging.info("Database connection closed.")
        except sqlite3.Error as e:
            logging.error(f"Failed to close the database connection: {e}")

# ========== User Account Class ==========
class UserAccount:
    def __init__(self, db_manager, user_id=None, name=None, email=None, password=None, phone=None, daily_limit=0, total_deposits=0,
                 loan_total=0, balance=0):
        self.db_manager = db_manager
        if user_id is not None:
            user_data = self.get_user_by_id(user_id)
            if user_data:
                self._initialize_from_db_data(user_data)
            else:
                raise ValueError("User not found.")
        else:
            if not all([name, email, password, phone]):
                raise ValueError("Name, email, password, and phone are required.")
            if not self.validate_name(name):
                raise ValueError("Invalid name format (2-12 chars, letters/numbers/underscore).")
            if not self.validate_email(email):
                raise ValueError("Invalid email format.")
            if not self.validate_password(password):
                raise ValueError("Password must be >=6 chars, contain at least one letter and one digit.")

            password_hash = self.hash_password(password)
            new_user_id = self.db_manager.add_user(name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance)
            if new_user_id is None:
                raise ValueError("Failed to create user.")
            user_data = self.get_user_by_id(new_user_id)
            if user_data:
                self._initialize_from_db_data(user_data)
            else:
                raise ValueError("Failed to retrieve user data after registration.")

    def _initialize_from_db_data(self, user_data):
        self.user_id = user_data[0]
        self.name = user_data[1]
        self.email = user_data[2]
        self.password_hash = user_data[3]
        self.phone = user_data[4]
        self.daily_limit = user_data[5]
        self.total_deposits = user_data[6]
        self.loan_total = user_data[7]
        self.balance = user_data[8]
        self.last_interest_update_time = user_data[9]
        logging.info(f"Initialized UserAccount for user ID {self.user_id}.")

    @staticmethod
    def validate_name(name):
        name = name.strip()
        if not (2 <= len(name) <= 12):
            return False
        pattern = r'^[A-Za-z0-9_]+$'
        return re.match(pattern, name) is not None

    @staticmethod
    def validate_email(email):
        pattern = r"[^@]+@[^@]+\.[^@]+"
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_password(password):
        if len(password) < 6:
            return False
        has_letter = bool(re.search(r"[A-Za-z]", password))
        has_digit = bool(re.search(r"\d", password))
        return has_letter and has_digit

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    @classmethod
    def load_from_db(cls, db_manager, email, password):
        user_data = db_manager.get_user_by_email(email)
        if user_data is None:
            logging.warning(f"No user found with email: {email}.")
            raise ValueError("No user found with this email.")
        stored_hash = user_data[3]
        input_hash = cls.hash_password(password)
        if input_hash == stored_hash:
            logging.info(f"User '{email}' authenticated successfully.")
            return cls(db_manager, user_id=user_data[0])
        else:
            logging.warning(f"Incorrect password attempt for email: {email}.")
            raise ValueError("Incorrect password.")

    def get_user_by_id(self, user_id):
        return self.db_manager.get_user_by_id(user_id)

    def deposit(self, amount):
        if amount <= 0:
            logging.warning(f"Attempted to deposit invalid amount: {amount}.")
            raise ValueError("Deposit amount must be positive.")
        self.balance += amount
        self.total_deposits += amount
        self.db_manager.update_user_balance(self.user_id, self.balance)
        self.db_manager.update_user_info(self.user_id, total_deposits=self.total_deposits)
        self.db_manager.record_transaction(self.user_id, amount, "deposit")
        logging.info(f"User ID {self.user_id} deposited {amount}. New balance: {self.balance}.")

    def withdraw(self, amount):
        if amount <= 0:
            logging.warning(f"Attempted to withdraw invalid amount: {amount}.")
            raise ValueError("Withdrawal amount must be positive.")
        if amount > self.balance:
            logging.warning(f"User ID {self.user_id} attempted to withdraw {amount} with balance {self.balance}.")
            raise ValueError("Insufficient funds.")
        if self.daily_limit and amount > self.daily_limit:
            logging.warning(f"User ID {self.user_id} attempted to withdraw {amount} exceeding daily limit {self.daily_limit}.")
            raise ValueError("Amount exceeds daily limit.")
        self.balance -= amount
        self.db_manager.update_user_balance(self.user_id, self.balance)
        self.db_manager.record_transaction(self.user_id, -amount, "withdraw")
        logging.info(f"User ID {self.user_id} withdrew {amount}. New balance: {self.balance}.")

    def update_personal_info(self, name=None, email=None, password=None, phone=None, daily_limit=None, loan_total=None):
        updates = {}
        if name and self.validate_name(name):
            updates['name'] = name
        if email and self.validate_email(email):
            updates['email'] = email
        if password:
            if not self.validate_password(password):
                logging.warning("Invalid password format during update.")
                raise ValueError("Password must be >=6 chars, contain letter and digit.")
            updates['password_hash'] = self.hash_password(password)
        if phone is not None:
            updates['phone'] = phone
        if daily_limit is not None:
            updates['daily_limit'] = daily_limit
        if loan_total is not None:
            updates['loan_total'] = loan_total

        if updates:
            self.db_manager.update_user_info(self.user_id, **updates)
            for k, v in updates.items():
                setattr(self, k, v)
            logging.info(f"User ID {self.user_id} updated personal info: {updates}.")

    def get_balance(self):
        return self.balance

# ========== Transaction Manager ==========
class TransactionManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def add_income(self, amount):
        self.user_account.deposit(amount)

    def add_expense(self, amount):
        self.user_account.withdraw(amount)

    def transfer(self, recipient_account, amount):
        if amount <= 0:
            logging.warning(f"Invalid transfer amount: {amount}.")
            raise ValueError("Amount must be positive")
        if self.user_account.get_balance() < amount:
            logging.warning(f"User ID {self.user_account.user_id} attempted to transfer {amount} with balance {self.user_account.get_balance()}.")
            raise ValueError("Insufficient funds")
        if self.user_account.daily_limit and amount > self.user_account.daily_limit:
            logging.warning(f"User ID {self.user_account.user_id} attempted to transfer {amount} exceeding daily limit {self.user_account.daily_limit}.")
            raise ValueError("Amount exceeds daily limit")
        self.user_account.withdraw(amount)
        recipient_account.deposit(amount)
        logging.info(f"User ID {self.user_account.user_id} transferred {amount} to user ID {recipient_account.user_id}.")

    def get_transaction_history(self):
        return self.db_manager.get_transactions(self.user_account.user_id)

# ========== Budget Manager ==========
class BudgetManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def set_budget(self, category, amount):
        if amount <= 0:
            logging.warning(f"Invalid budget amount: {amount}.")
            raise ValueError("Budget amount must be positive")
        self.db_manager.set_budget(self.user_account.user_id, category, amount)
        logging.info(f"User ID {self.user_account.user_id} set budget for '{category}' with amount {amount}.")

    def get_budget_report(self):
        return self.db_manager.get_budgets(self.user_account.user_id)

# ========== Debt Manager ==========
class DebtManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def add_debt(self, debt_name, amount, annual_rate, years):
        if amount <= 0:
            logging.warning(f"Invalid debt amount: {amount}.")
            raise ValueError("Debt amount must be positive.")
        if annual_rate < 0:
            logging.warning(f"Invalid annual rate: {annual_rate}.")
            raise ValueError("Annual rate cannot be negative.")
        if years <= 0:
            logging.warning(f"Invalid loan period: {years}.")
            raise ValueError("Years must be greater than zero.")
        due_date = (datetime.now() + timedelta(days=365 * years)).date().isoformat()
        debt_id = self.db_manager.add_debt(self.user_account.user_id, debt_name, amount, annual_rate, years, due_date)
        if debt_id:
            self.user_account.balance += amount
            self.db_manager.update_user_balance(self.user_account.user_id, self.user_account.balance)
            self.db_manager.record_transaction(self.user_account.user_id, amount, "loan_received")
            logging.info(f"User ID {self.user_account.user_id} received loan '{debt_name}' of amount {amount}.")

    def pay_debt(self, debt_id, amount):
        self.db_manager.pay_debt(self.user_account.user_id, debt_id, amount)
        self.user_account.balance -= amount
        self.db_manager.update_user_balance(self.user_account.user_id, self.user_account.balance)
        self.db_manager.record_transaction(self.user_account.user_id, -amount, "debt_payment")
        logging.info(f"User ID {self.user_account.user_id} paid {amount} towards debt ID {debt_id}.")

    def view_debts(self):
        return self.db_manager.get_debts(self.user_account.user_id)

    def calculate_debt_future_value(self, debt_id):
        debts = self.db_manager.get_debts(self.user_account.user_id)
        debt = next((d for d in debts if d[0] == debt_id), None)
        if not debt:
            logging.warning(f"Debt ID {debt_id} not found for user ID {self.user_account.user_id}.")
            raise ValueError("Debt not found.")
        _, _, debt_name, principal, annual_rate, years, _ = debt
        rate_per_period = annual_rate / 100 / 12
        total_periods = years * 12
        future_value = principal * ((1 + rate_per_period) ** total_periods)
        logging.info(f"Calculated future value for debt '{debt_name}' (ID {debt_id}): {future_value:.2f}.")
        return debt_name, future_value

    def check_due_debts(self):
        debts = self.db_manager.get_debts(self.user_account.user_id)
        today = datetime.now().date()
        overdue = []
        upcoming = []
        for debt in debts:
            _, _, debt_name, amount, annual_rate, years, due_date_str = debt
            due_date = datetime.fromisoformat(due_date_str).date()
            if due_date < today:
                overdue.append((debt_name, due_date))
            elif due_date <= today + timedelta(days=7):
                upcoming.append((debt_name, due_date))
        logging.info(f"Checked due debts for user ID {self.user_account.user_id}. Overdue: {overdue}, Upcoming: {upcoming}.")
        return overdue, upcoming

# ========== Expense Categorization ==========
class ExpenseCategorization:
    def __init__(self):
        self.expenses = {}

    def categorize_expense(self, category, amount):
        if amount <= 0:
            logging.warning(f"Invalid expense amount: {amount}.")
            raise ValueError("Expense amount must be positive")
        if category not in self.expenses:
            self.expenses[category] = 0
        self.expenses[category] += amount
        logging.info(f"Categorized expense: {category} += {amount}.")

    def get_expense_report(self):
        return self.expenses

# ========== Savings Calculator ==========
class SavingsCalculator:
    def __init__(self, user_account):
        self.user_account = user_account

    def suggest_savings_plan(self, target_savings, months):
        if target_savings <= 0 or months <= 0:
            logging.warning(f"Invalid savings plan parameters: target={target_savings}, months={months}.")
            raise ValueError("Target savings and months must be positive.")
        monthly_savings = target_savings / months
        current_balance = self.user_account.get_balance()
        if current_balance >= target_savings:
            logging.info("Savings goal already met.")
            return "Your savings goal is already met."
        else:
            logging.info(f"Suggested monthly savings: {monthly_savings:.2f} for {months} months.")
            return f"Save {monthly_savings:.2f} per month for {months} months to reach your target."

    def compound_savings(self, principal, annual_rate, years, compounding_periods=12):
        if principal < 0 or annual_rate < 0 or years < 0:
            logging.warning(f"Invalid compound savings parameters: principal={principal}, rate={annual_rate}, years={years}.")
            raise ValueError("Invalid input.")
        rate_per_period = annual_rate / compounding_periods
        total_periods = compounding_periods * years
        future_value = principal * ((1 + rate_per_period) ** total_periods)
        logging.info(f"Calculated compound savings future value: {future_value:.2f}.")
        return future_value

# ========== Auto Financial Advisor ==========
class AutoFinancialAdvisor:
    def __init__(self, user_account):
        self.user_account = user_account

    def give_advice(self):
        balance = self.user_account.get_balance()
        if balance > 5000:
            advice = "You are in a great financial position! Consider investing."
        elif balance > 1000:
            advice = "Your finances are stable, consider saving more."
        else:
            advice = "Focus on building savings. Consider reducing expenses."
        logging.info(f"Provided financial advice based on balance {balance}: {advice}")
        return advice

# ========== Data Visualization ==========
class DataVisualization:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def get_balance_over_time(self):
        records = self.db_manager.get_transactions(self.user_account.user_id)
        if not records:
            logging.info(f"No transactions found for balance over time visualization for user ID {self.user_account.user_id}.")
            return [], []
        sorted_records = sorted(records, key=lambda x: x[4])
        initial_balance = self.user_account.balance
        for record in sorted_records:
            initial_balance -= record[2]
        current_balance = initial_balance

        balances = []
        timestamps = []
        for record in sorted_records:
            current_balance += record[2]
            balances.append(current_balance)
            timestamps.append(datetime.fromisoformat(record[4]))
        logging.info(f"Prepared balance over time data for user ID {self.user_account.user_id}.")
        return timestamps, balances

# ========== GUI: Login and Main Window ==========
class LoginWindow:
    def __init__(self, master, db_manager):
        self.master = master
        self.master.title("User Login")

        self.master.geometry("350x200")
        self.master.resizable(False, False)

        self.db_manager = db_manager

        style = ttk.Style()
        style.theme_use("clam")

        style.configure('TLabel', font=('Arial', 10))
        style.configure('TButton', font=('Arial', 10))
        style.configure('TEntry', font=('Arial', 10))

        title_label = ttk.Label(master, text="Welcome to the Banking System", font=('Arial', 14, 'bold'))
        title_label.pack(pady=10)

        form_frame = ttk.Frame(master)
        form_frame.pack(pady=5)

        ttk.Label(form_frame, text="Email:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(form_frame, show="*", width=25)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(master)
        btn_frame.pack(pady=10)

        login_button = ttk.Button(btn_frame, text="Login", command=self.login)
        login_button.grid(row=0, column=0, padx=5)
        register_button = ttk.Button(btn_frame, text="Register", command=self.register)
        register_button.grid(row=0, column=1, padx=5)

    def login(self):
        email = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        try:
            user = UserAccount.load_from_db(self.db_manager, email, pwd)
            messagebox.showinfo("Success", "Login successful.")
            MainWindow(self.master, self.db_manager, user)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def register(self):
        reg_window = tk.Toplevel(self.master)
        reg_window.title("Register")
        reg_window.geometry("300x250")
        reg_window.resizable(False, False)

        ttk.Label(reg_window, text="Name:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        name_entry = ttk.Entry(reg_window)
        name_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(reg_window, text="Email:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        email_entry = ttk.Entry(reg_window)
        email_entry.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(reg_window, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky='e')
        pwd_entry = ttk.Entry(reg_window, show='*')
        pwd_entry.grid(row=2, column=1, padx=10, pady=10)

        ttk.Label(reg_window, text="Phone:").grid(row=3, column=0, padx=10, pady=10, sticky='e')
        phone_entry = ttk.Entry(reg_window)
        phone_entry.grid(row=3, column=1, padx=10, pady=10)

        def do_register():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            pwd = pwd_entry.get().strip()
            phone = phone_entry.get().strip()
            try:
                UserAccount(self.db_manager, name=name, email=email, password=pwd, phone=phone, balance=0)
                messagebox.showinfo("Success", "User registered successfully.")
                reg_window.destroy()
            except ValueError as ex:
                messagebox.showerror("Error", str(ex))

        submit_btn = ttk.Button(reg_window, text="Submit", command=do_register)
        submit_btn.grid(row=4, column=0, columnspan=2, pady=20)

class MainWindow:
    def __init__(self, master, db_manager, user):
        self.root = tk.Toplevel(master)
        self.root.title("Main Menu")
        # Use a canvas and scrollbar for a scrollable frame
        self.root.geometry("500x600")
        self.root.resizable(True, True)

        self.db_manager = db_manager
        self.user = user

        style = ttk.Style()
        style.configure('MainMenu.TFrame', background='#f0f0f0')
        style.configure('Section.TLabelframe', font=('Arial', 12, 'bold'), foreground='#333333')
        style.configure('TButton', font=('Arial', 10))

        canvas = tk.Canvas(self.root)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        scrollable_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        scrollable_frame.bind("<Configure>", on_configure)
        canvas.configure(yscrollcommand=scrollbar.set)

        title_label = ttk.Label(scrollable_frame, text=f"Hello, {self.user.name}", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)

        self.tm = TransactionManager(db_manager, user)
        self.dm = DebtManager(db_manager, user)
        self.bm = BudgetManager(db_manager, user)
        self.ec = ExpenseCategorization()
        self.sc = SavingsCalculator(user)
        self.adv = AutoFinancialAdvisor(user)
        self.viz = DataVisualization(db_manager, user)

        overdue, upcoming = self.dm.check_due_debts()
        if overdue:
            msg = "Overdue Debts:\n" + "\n".join([f"{d[0]} due {d[1]}" for d in overdue])
            messagebox.showwarning("Overdue Debts", msg)
        if upcoming:
            msg = "Debts due within a week:\n" + "\n".join([f"{d[0]} due {d[1]}" for d in upcoming])
            messagebox.showinfo("Upcoming Debts", msg)

        account_frame = ttk.Labelframe(scrollable_frame, text="Account Operations", style='Section.TLabelframe')
        account_frame.pack(fill='x', pady=10)
        ttk.Button(account_frame, text="View Current Balance", command=self.view_balance, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(account_frame, text="Deposit", command=self.deposit, width=25).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(account_frame, text="Withdraw", command=self.withdraw, width=25).grid(row=2, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(account_frame, text="Transfer", command=self.transfer, width=25).grid(row=3, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(account_frame, text="View Transaction History", command=self.view_transactions, width=25).grid(row=4, column=0, padx=5, pady=5, sticky='w')

        budget_frame = ttk.Labelframe(scrollable_frame, text="Budget & Expenses", style='Section.TLabelframe')
        budget_frame.pack(fill='x', pady=10)
        ttk.Button(budget_frame, text="Set Budget", command=self.set_budget, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(budget_frame, text="Add Expense", command=self.add_expense, width=25).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(budget_frame, text="View Expense Report", command=self.view_expense_report, width=25).grid(row=2, column=0, padx=5, pady=5, sticky='w')

        debt_frame = ttk.Labelframe(scrollable_frame, text="Debt Management", style='Section.TLabelframe')
        debt_frame.pack(fill='x', pady=10)
        ttk.Button(debt_frame, text="Manage Debts", command=self.manage_debts, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')

        savings_frame = ttk.Labelframe(scrollable_frame, text="Savings & Advice", style='Section.TLabelframe')
        savings_frame.pack(fill='x', pady=10)
        ttk.Button(savings_frame, text="Savings Plan", command=self.savings_plan, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(savings_frame, text="View Financial Advice", command=self.view_advice, width=25).grid(row=1, column=0, padx=5, pady=5, sticky='w')

        analysis_frame = ttk.Labelframe(scrollable_frame, text="Analysis & Interest", style='Section.TLabelframe')
        analysis_frame.pack(fill='x', pady=10)
        ttk.Button(analysis_frame, text="View Balance Over Time", command=self.view_balance_over_time, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Button(analysis_frame, text="View Daily Interest", command=self.view_daily_interest, width=25).grid(row=1, column=0, padx=5, pady=5, sticky='w')

        info_frame = ttk.Labelframe(scrollable_frame, text="User Settings", style='Section.TLabelframe')
        info_frame.pack(fill='x', pady=10)
        ttk.Button(info_frame, text="Update Personal Info", command=self.update_personal_info, width=25).grid(row=0, column=0, padx=5, pady=5, sticky='w')

        exit_button = ttk.Button(scrollable_frame, text="Exit", command=self.exit_app, width=25)
        exit_button.pack(pady=20)

    def deposit(self):
        amount = self.ask_amount("Deposit Amount")
        if amount is None:
            return
        try:
            self.tm.add_income(amount)
            messagebox.showinfo("Success", f"Deposited {amount:.2f}. New Balance: {self.user.get_balance():.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def withdraw(self):
        amount = self.ask_amount("Withdrawal Amount")
        if amount is None:
            return
        try:
            self.tm.add_expense(amount)
            messagebox.showinfo("Success", f"Withdrew {amount:.2f}. New Balance: {self.user.get_balance():.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def transfer(self):
        recipient_email = simpledialog.askstring("Transfer", "Enter recipient's email:")
        if not recipient_email:
            return
        recipient_data = self.db_manager.get_user_by_email(recipient_email)
        if not recipient_data:
            messagebox.showerror("Error", "Recipient not found.")
            return
        pwd = simpledialog.askstring("Verify", "Enter your password:", show='*')
        if UserAccount.hash_password(pwd) != self.user.password_hash:
            messagebox.showerror("Error", "Incorrect password.")
            return
        recipient = UserAccount(self.db_manager, user_id=recipient_data[0])
        amount = self.ask_amount("Transfer Amount")
        if amount is None:
            return
        try:
            self.tm.transfer(recipient, amount)
            messagebox.showinfo("Success", f"Transferred {amount:.2f}. New Balance: {self.user.get_balance():.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def view_transactions(self):
        records = self.tm.get_transaction_history()
        win = tk.Toplevel(self.root)
        win.title("Transaction History")
        win.geometry("600x300")

        if not records:
            ttk.Label(win, text="No transactions found.").pack(padx=10, pady=10)
            return
        tree = ttk.Treeview(win, columns=("ID", "Amount", "Type", "Time"), show='headings')
        tree.heading("ID", text="ID")
        tree.heading("Amount", text="Amount")
        tree.heading("Type", text="Type")
        tree.heading("Time", text="Time")
        tree.column("ID", width=50)
        tree.column("Amount", width=80)
        tree.column("Type", width=120)
        tree.column("Time", width=250)
        tree.pack(fill=tk.BOTH, expand=True)
        for record in records:
            tree.insert("", tk.END, values=(record[0], f"{record[2]:.2f}", record[3], record[4]))

    def set_budget(self):
        category = simpledialog.askstring("Set Budget", "Enter category:")
        if not category:
            return
        amount = self.ask_amount("Budget Amount")
        if amount is None:
            return
        try:
            self.bm.set_budget(category, amount)
            messagebox.showinfo("Success", f"Budget set for {category}: {amount:.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def view_expense_report(self):
        report = self.ec.get_expense_report()
        win = tk.Toplevel(self.root)
        win.title("Expense Report")
        win.geometry("300x200")

        if not report:
            ttk.Label(win, text="No expenses recorded.").pack(padx=10, pady=10)
            return
        text = "\n".join([f"{cat}: {amt:.2f}" for cat, amt in report.items()])
        ttk.Label(win, text=text).pack(padx=10, pady=10)

    def add_expense(self):
        category = simpledialog.askstring("Add Expense", "Enter category:")
        if not category:
            return
        amount = self.ask_amount("Expense Amount")
        if amount is None:
            return
        try:
            self.ec.categorize_expense(category, amount)
            messagebox.showinfo("Success", f"Expense added to {category}: {amount:.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def savings_plan(self):
        target = self.ask_amount("Target Savings")
        if target is None:
            return
        months = simpledialog.askinteger("Savings Plan", "Enter number of months:")
        if not months:
            return
        try:
            plan = self.sc.suggest_savings_plan(target, months)
            messagebox.showinfo("Savings Plan", plan)
            future_value = self.sc.compound_savings(self.user.balance, 0.05, 5)
            if future_value is not None:
                messagebox.showinfo("Future Value", f"Future value after 5 years at 5%: {future_value:.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def view_advice(self):
        advice = self.adv.give_advice()
        messagebox.showinfo("Financial Advice", advice)

    def view_balance_over_time(self):
        timestamps, balances = self.viz.get_balance_over_time()
        if not timestamps:
            messagebox.showinfo("Info", "No transactions to display.")
            return
        fig = plt.Figure(figsize=(6,4))
        ax = fig.add_subplot(111)
        ax.plot(timestamps, balances, marker='o', color='#3366cc')
        ax.set_title("Balance Over Time", fontweight='bold')
        ax.set_xlabel("Time")
        ax.set_ylabel("Balance")
        fig.autofmt_xdate()

        win = tk.Toplevel(self.root)
        win.title("Balance Over Time")
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_personal_info(self):
        win = tk.Toplevel(self.root)
        win.title("Update Personal Info")
        win.geometry("300x300")

        fields = [("Name", None), ("Email", None), ("Password", None), ("Phone", None), ("Daily Limit", float), ("Loan Total", float)]
        entries = {}

        for i, (label_txt, conv) in enumerate(fields):
            ttk.Label(win, text=f"{label_txt}:").grid(row=i, column=0, padx=5, pady=5, sticky='e')
            e = ttk.Entry(win, width=20)
            e.grid(row=i, column=1, padx=5, pady=5)
            entries[label_txt] = (e, conv)

        def do_update():
            kwargs = {}
            for label_txt, (entry, conv) in entries.items():
                val = entry.get().strip()
                if val:
                    if conv:
                        try:
                            val = conv(val)
                        except ValueError:
                            messagebox.showerror("Error", f"{label_txt} must be a number.")
                            return
                    param_name = label_txt.lower().replace(" ", "_")
                    kwargs[param_name] = val
            try:
                self.user.update_personal_info(
                    name=kwargs.get("name"),
                    email=kwargs.get("email"),
                    password=kwargs.get("password"),
                    phone=kwargs.get("phone"),
                    daily_limit=kwargs.get("daily_limit"),
                    loan_total=kwargs.get("loan_total")
                )
                messagebox.showinfo("Success", "Information updated.")
                win.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Update", command=do_update).grid(row=len(fields), column=0, columnspan=2, pady=20)

    def manage_debts(self):
        menu = tk.Toplevel(self.root)
        menu.title("Debt Management")
        menu.geometry("300x250")

        ttk.Button(menu, text="Add Debt", command=self.add_debt_action).pack(padx=10, pady=10, fill='x')
        ttk.Button(menu, text="Pay Debt", command=self.pay_debt_action).pack(padx=10, pady=10, fill='x')
        ttk.Button(menu, text="View Debts", command=self.show_debts).pack(padx=10, pady=10, fill='x')
        ttk.Button(menu, text="Calculate Future Value", command=self.calc_future_value).pack(padx=10, pady=10, fill='x')

    def add_debt_action(self):
        name = simpledialog.askstring("Add Debt", "Debt Name:")
        if not name:
            return
        amount = self.ask_amount("Debt Amount")
        if amount is None:
            return
        annual_rate = simpledialog.askfloat("Add Debt", "Annual Rate (%):")
        if annual_rate is None:
            return
        years = simpledialog.askinteger("Add Debt", "Loan Period (years):")
        if years is None:
            return
        try:
            self.dm.add_debt(name, amount, annual_rate, years)
            messagebox.showinfo("Success", f"Debt '{name}' added.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def pay_debt_action(self):
        debt_id = simpledialog.askinteger("Pay Debt", "Debt ID:")
        if not debt_id:
            return
        amount = self.ask_amount("Payment Amount")
        if amount is None:
            return
        try:
            self.dm.pay_debt(debt_id, amount)
            messagebox.showinfo("Success", "Debt paid.")
        except (ValueError, sqlite3.Error) as e:
            messagebox.showerror("Error", str(e))

    def show_debts(self):
        debts = self.dm.view_debts()
        w = tk.Toplevel(self.root)
        w.title("Your Debts")
        w.geometry("600x300")
        if not debts:
            ttk.Label(w, text="No debts found.").pack(padx=10, pady=10)
            return
        tree = ttk.Treeview(w, columns=("ID","Name","Amount","Rate","Years","Due"), show='headings')
        for col in ("ID","Name","Amount","Rate","Years","Due"):
            tree.heading(col, text=col)
        tree.column("ID", width=50)
        tree.column("Name", width=100)
        tree.column("Amount", width=80)
        tree.column("Rate", width=80)
        tree.column("Years", width=60)
        tree.column("Due", width=120)
        tree.pack(fill=tk.BOTH, expand=True)
        for d in debts:
            tree.insert("", tk.END, values=(d[0],d[2],f"{d[3]:.2f}",f"{d[4]}%",d[5],d[6]))

    def calc_future_value(self):
        debt_id = simpledialog.askinteger("Calculate Future Value", "Debt ID:")
        if not debt_id:
            return
        try:
            name, fv = self.dm.calculate_debt_future_value(debt_id)
            messagebox.showinfo("Future Value", f"Future Value of '{name}': {fv:.2f}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def view_balance(self):
        messagebox.showinfo("Current Balance", f"Your current balance is: {self.user.get_balance():.2f}")

    def view_daily_interest(self):
        records = self.db_manager.get_daily_interest_records(self.user.user_id, days=7)
        win = tk.Toplevel(self.root)
        win.title("Daily Interest (Last 7 Days)")
        win.geometry("400x250")
        if not records:
            ttk.Label(win, text="No interest records found.").pack(padx=10, pady=10)
            return
        tree = ttk.Treeview(win, columns=("Date","Interest"), show='headings')
        tree.heading("Date", text="Date")
        tree.heading("Interest", text="Interest Amount")
        tree.column("Date", width=100)
        tree.column("Interest", width=100)
        tree.pack(fill=tk.BOTH, expand=True)
        for r in records:
            tree.insert("", tk.END, values=(r[0], f"{r[1]:.2f}"))

    def exit_app(self):
        self.db_manager.close()
        self.root.destroy()
        self.master.destroy()
        logging.info("Application exited by user.")

    def ask_amount(self, prompt):
        val = simpledialog.askfloat("Input", prompt+":", minvalue=0.0)
        return val

# ========== Scheduler for Automatic Interest Update ==========
def schedule_interest_updates(db_manager):
    schedule.every().day.at("00:00").do(db_manager.update_all_users_interest)
    logging.info("Scheduled daily interest updates at 00:00.")

    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

# ========== Main Function ==========
def main():
    db_manager = DatabaseManager()
    db_manager.update_all_users_interest()  # Initial interest update

    # Start the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=schedule_interest_updates, args=(db_manager,), daemon=True)
    scheduler_thread.start()

    root = tk.Tk()
    LoginWindow(root, db_manager)
    root.mainloop()

if __name__ == "__main__":
    main()
