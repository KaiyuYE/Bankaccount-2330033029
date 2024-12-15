import re
import sqlite3
from datetime import datetime, timedelta
import hashlib
import matplotlib.pyplot as plt

# ========== Database Initialization and Management ==========
class DatabaseManager:
    def __init__(self, db_name="banking.db"):
        """
        Initialize the database connection, create required tables,
        and create indexes for query optimization.
        """
        try:
            self.conn = sqlite3.connect(db_name)
            self.create_tables()
            self.create_indexes()  # Create indexes for query optimization
        except sqlite3.Error as e:
            print(f"Database connection failed: {e}")

    def create_tables(self):
        """
        Create the users table, transactions table, and debts table.
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                # Users table: Stores username, email, hashed password, phone number, daily limit, total deposits, loan total, balance, and last login time
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
                                    last_login TEXT
                                  )''')

                # Transactions table: Stores transaction records
                cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (
                                    transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    amount REAL,
                                    transaction_type TEXT,
                                    timestamp TEXT,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')

                # Debts table: Stores debt records
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
        except sqlite3.Error as e:
            print(f"Failed to create tables: {e}")

    def create_indexes(self):
        """
        Create indexes to optimize searches.
        Create an index on email to speed up user queries by email.
        """
        try:
            with self.conn:
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        except sqlite3.Error as e:
            print(f"Failed to create index: {e}")

    def add_user(self, name, email, password_hash, phone, daily_limit=0, total_deposits=0, loan_total=0, balance=0):
        """
        Add a new user (password is stored as a hash).
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""INSERT INTO users (name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance, last_login) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                               (name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance, datetime.now().isoformat()))
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            print("Error: This email is already registered.")
            return None
        except sqlite3.Error as e:
            print(f"Failed to add user: {e}")
            return None

    def get_user_by_email(self, email):
        """
        Query user information by email.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            return cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Failed to query user: {e}")
            return None

    def update_user_balance(self, user_id, new_balance):
        """
        Update user balance.
        """
        try:
            with self.conn:
                self.conn.execute("UPDATE users SET balance = ? WHERE user_id = ?", (new_balance, user_id))
        except sqlite3.Error as e:
            print(f"Failed to update user balance: {e}")

    def update_user_info(self, user_id, **kwargs):
        """
        Update user information, optional fields include name, email, password_hash, phone, daily_limit, total_deposits, loan_total, balance, last_login.
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                for key, value in kwargs.items():
                    if value is not None:
                        cursor.execute(f"UPDATE users SET {key} = ? WHERE user_id = ?", (value, user_id))
        except sqlite3.Error as e:
            print(f"Failed to update user information: {e}")

    def record_transaction(self, user_id, amount, transaction_type):
        """
        Record a transaction.
        """
        try:
            with self.conn:
                timestamp = datetime.now().isoformat()
                self.conn.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                     VALUES (?, ?, ?, ?)""",
                                  (user_id, amount, transaction_type, timestamp))
        except sqlite3.Error as e:
            print(f"Failed to record transaction: {e}")

    def get_transactions(self, user_id):
        """
        Get all transaction records for a specific user, sorted by time.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp", (user_id,))
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Failed to query transactions: {e}")
            return []

    def add_debt(self, user_id, debt_name, amount, annual_rate, years, due_date):
        """
        Add a debt record and record it as a transaction.
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""INSERT INTO debts (user_id, debt_name, amount, annual_rate, years, due_date) 
                                  VALUES (?, ?, ?, ?, ?, ?)""",
                               (user_id, debt_name, amount, annual_rate, years, due_date))
                debt_id = cursor.lastrowid
                # Update the user's loan_total
                cursor.execute("UPDATE users SET loan_total = loan_total + ? WHERE user_id = ?", (amount, user_id))
                # Record a debt addition transaction
                cursor.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, amount, "debt_addition", datetime.now().isoformat()))
                return debt_id
        except sqlite3.Error as e:
            print(f"Failed to add debt: {e}")
            return None

    def get_debts(self, user_id):
        """
        Get all debt records for a specific user.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM debts WHERE user_id = ?", (user_id,))
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Failed to query debts: {e}")
            return []

    def pay_debt(self, user_id, debt_id, amount):
        """
        Pay a debt and record it as a transaction.
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("SELECT amount FROM debts WHERE debt_id = ? AND user_id = ?", (debt_id, user_id))
                result = cursor.fetchone()
                if not result:
                    raise ValueError("Debt not found.")
                current_amount = result[0]
                if amount <= 0:
                    raise ValueError("Payment amount must be positive.")
                if amount > current_amount:
                    raise ValueError("Payment exceeds debt amount.")
                new_amount = current_amount - amount
                if new_amount == 0:
                    cursor.execute("DELETE FROM debts WHERE debt_id = ?", (debt_id,))
                else:
                    cursor.execute("UPDATE debts SET amount = ? WHERE debt_id = ?", (new_amount, debt_id))
                # Update the user's loan_total
                cursor.execute("UPDATE users SET loan_total = loan_total - ? WHERE user_id = ?", (amount, user_id))
                # Record a debt payment transaction
                cursor.execute("""INSERT INTO transactions (user_id, amount, transaction_type, timestamp) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, -amount, "debt_payment", datetime.now().isoformat()))
        except sqlite3.Error as e:
            print(f"Failed to pay debt: {e}")
            raise
        except ValueError as ve:
            print(f"Error: {ve}")
            raise

    def set_budget(self, user_id, category, amount):
        """
        Set a budget. Make sure the budgets table exists first.
        """
        try:
            with self.conn:
                cursor = self.conn.cursor()
                # If the budgets table does not exist, create it
                cursor.execute('''CREATE TABLE IF NOT EXISTS budgets (
                                    budget_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    user_id INTEGER,
                                    category TEXT,
                                    amount REAL,
                                    created_at TEXT,
                                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                                  )''')
                created_at = datetime.now().isoformat()
                cursor.execute("""INSERT INTO budgets (user_id, category, amount, created_at) 
                                  VALUES (?, ?, ?, ?)""",
                               (user_id, category, amount, created_at))
        except sqlite3.Error as e:
            print(f"Failed to set budget: {e}")

    def get_budgets(self, user_id):
        """
        Get all budget records for a specific user.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM budgets WHERE user_id = ?", (user_id,))
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Failed to get budget records: {e}")
            return []

    def close(self):
        """
        Close the database connection.
        """
        try:
            self.conn.close()
        except sqlite3.Error as e:
            print(f"Failed to close the database connection: {e}")


# ========== User Account Class and Management ==========
class UserAccount:
    def __init__(self, db_manager, user_id=None, name=None, email=None, password=None, phone=None, daily_limit=0, total_deposits=0,
                 loan_total=0, balance=0):
        self.db_manager = db_manager

        if user_id is not None:
            # Load user info by user_id
            user_data = self.get_user_by_id(user_id)
            if user_data:
                self._initialize_from_db_data(user_data)
            else:
                raise ValueError("User not found.")
        else:
            # Create a new user
            if not all([name, email, password, phone]):
                raise ValueError("Name, email, password, and phone are required to create a new account.")

            if not self.validate_name(name):
                raise ValueError("Invalid name format. Name must be 2-12 characters long and can only include letters, numbers, and underscores.")
            if not self.validate_email(email):
                raise ValueError("Invalid email format.")
            if not self.validate_password(password):
                # If the password does not meet the requirements, provide a prompt
                raise ValueError("Password must be at least 6 characters long and contain at least one letter and one digit.")

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
        self.last_login = user_data[9]

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
            raise ValueError("No user found with this email. Please register.")
        stored_hash = user_data[3]
        input_hash = cls.hash_password(password)
        if input_hash == stored_hash:
            user = cls(db_manager, user_id=user_data[0])
            user.apply_interest()  # Update interest upon login
            return user
        else:
            # Provide password format prompt
            raise ValueError("Incorrect password. Password must be at least 7 characters long and contain at least one letter and one digit.")

    def get_user_by_id(self, user_id):
        cursor = self.db_manager.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user_data = cursor.fetchone()
        return user_data

    def apply_interest(self):
        """
        Calculate interest based on the time interval since the user's last login (example annual rate 2%).
        """
        if not self.last_login:
            self.db_manager.update_user_info(self.user_id, last_login=datetime.now().isoformat())
            return
        last_login_time = datetime.fromisoformat(self.last_login)
        now = datetime.now()
        delta_days = (now - last_login_time).days
        if delta_days > 0:
            annual_rate = 0.02
            daily_rate = annual_rate / 365
            new_balance = self.balance * ((1 + daily_rate) ** delta_days)
            self.balance = new_balance
            self.db_manager.update_user_balance(self.user_id, self.balance)
            self.db_manager.update_user_info(self.user_id, last_login=now.isoformat())

    def deposit(self, amount):
        try:
            if amount <= 0:
                raise ValueError("Deposit amount must be positive")
            self.balance += amount
            self.total_deposits += amount
            self.db_manager.update_user_balance(self.user_id, self.balance)
            self.db_manager.update_user_info(self.user_id, total_deposits=self.total_deposits)
            self.db_manager.record_transaction(self.user_id, amount, "deposit")
            print(f"Deposited {amount:.2f}. New balance: {self.balance:.2f}")
        except ValueError as e:
            print(f"Error: {e}")

    def withdraw(self, amount):
        try:
            if amount <= 0:
                raise ValueError("Withdrawal amount must be positive")
            if amount > self.balance:
                raise ValueError("Insufficient funds")
            if self.daily_limit and amount > self.daily_limit:
                raise ValueError("Amount exceeds daily limit")
            self.balance -= amount
            self.db_manager.update_user_balance(self.user_id, self.balance)
            self.db_manager.record_transaction(self.user_id, -amount, "withdraw")
            print(f"Withdrew {amount:.2f}. New balance: {self.balance:.2f}")
        except ValueError as e:
            print(f"Error: {e}")

    def update_personal_info(self, name=None, email=None, password=None, phone=None, daily_limit=None, loan_total=None):
        if password:
            if not self.validate_password(password):
                print("Error: Password must be at least 7 characters long and contain at least one letter and one digit.")
                password_hash = None
            else:
                password_hash = self.hash_password(password)
        else:
            password_hash = None

        updates = {}
        if name and self.validate_name(name):
            updates['name'] = name
        if email and self.validate_email(email):
            updates['email'] = email
        if password_hash:
            updates['password_hash'] = password_hash
        if phone is not None:
            updates['phone'] = phone
        if daily_limit is not None:
            updates['daily_limit'] = daily_limit
        if loan_total is not None:
            updates['loan_total'] = loan_total

        if updates:
            try:
                self.db_manager.update_user_info(self.user_id, **updates)
                print("Personal information updated successfully.")
                for k, v in updates.items():
                    setattr(self, k, v)
            except Exception as e:
                print(f"Error updating information: {e}")
        else:
            print("No valid updates provided.")

    def get_balance(self):
        return self.balance


# ========== Transaction Manager ==========
class TransactionManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def add_income(self, amount):
        try:
            if amount <= 0:
                raise ValueError("Income amount must be positive")
            self.user_account.deposit(amount)
        except ValueError as e:
            print(f"Error: {e}")

    def add_expense(self, amount):
        try:
            if amount <= 0:
                raise ValueError("Expense amount must be positive")
            self.user_account.withdraw(amount)
        except ValueError as e:
            print(f"Error: {e}")

    def transfer(self, recipient_account, amount):
        try:
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if self.user_account.get_balance() < amount:
                raise ValueError("Insufficient funds")
            if self.user_account.daily_limit and amount > self.user_account.daily_limit:
                raise ValueError("Amount exceeds daily limit")
            self.user_account.withdraw(amount)
            recipient_account.deposit(amount)
            print(f"Transferred {amount:.2f} to {recipient_account.name}. Your new balance: {self.user_account.get_balance():.2f}")
        except ValueError as e:
            print(f"Error: {e}")

    def get_transaction_history(self):
        records = self.db_manager.get_transactions(self.user_account.user_id)
        if not records:
            print("No transactions found.")
            return
        print("\n--- Transaction History ---")
        for record in records:
            transaction_id, user_id, amount, transaction_type, timestamp = record
            print(f"ID: {transaction_id}, Amount: {amount:.2f}, Type: {transaction_type}, Time: {timestamp}")


# ========== Budget Manager ==========
class BudgetManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def set_budget(self, category, amount):
        try:
            if amount <= 0:
                raise ValueError("Budget amount must be positive")
            self.db_manager.set_budget(self.user_account.user_id, category, amount)
            print(f"Budget for '{category}' set to {amount:.2f}.")
        except ValueError as e:
            print(f"Error: {e}")

    def get_budget_report(self):
        budgets = self.db_manager.get_budgets(self.user_account.user_id)
        if not budgets:
            print("No budgets set.")
            return
        print("\n--- Current Budgets ---")
        for budget in budgets:
            budget_id, user_id, category, amount, created_at = budget
            print(f"Category: {category}, Amount: {amount:.2f}, Created At: {created_at}")


# ========== Debt Manager ==========
class DebtManager:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def add_debt(self, debt_name, amount, annual_rate, years):
        try:
            if amount <= 0:
                raise ValueError("Debt amount must be positive.")
            if annual_rate < 0:
                raise ValueError("Annual rate cannot be negative.")
            if years <= 0:
                raise ValueError("Years must be greater than zero.")
            due_date = (datetime.now() + timedelta(days=365 * years)).date().isoformat()
            debt_id = self.db_manager.add_debt(self.user_account.user_id, debt_name, amount, annual_rate, years, due_date)
            if debt_id:
                print(f"Debt '{debt_name}' of amount {amount:.2f} added successfully with ID {debt_id}. Due on {due_date}.")
                self.user_account.balance += amount
                self.db_manager.update_user_balance(self.user_account.user_id, self.user_account.balance)
                self.db_manager.record_transaction(self.user_account.user_id, amount, "loan_received")
        except ValueError as e:
            print(f"Error: {e}")

    def pay_debt(self, debt_id, amount):
        try:
            self.db_manager.pay_debt(self.user_account.user_id, debt_id, amount)
            print(f"Paid {amount:.2f} towards debt ID {debt_id} successfully.")
            self.user_account.balance -= amount
            self.db_manager.update_user_balance(self.user_account.user_id, self.user_account.balance)
            self.db_manager.record_transaction(self.user_account.user_id, -amount, "debt_payment")
        except (ValueError, sqlite3.Error) as e:
            print(f"Error: {e}")

    def view_debts(self):
        debts = self.db_manager.get_debts(self.user_account.user_id)
        if not debts:
            print("No debts found.")
            return
        print("\n--- Your Debts ---")
        for debt in debts:
            debt_id, user_id, debt_name, amount, annual_rate, years, due_date = debt
            print(f"ID: {debt_id}, Name: {debt_name}, Amount: {amount:.2f}, Annual Rate: {annual_rate}%, Years: {years}, Due Date: {due_date}")

    def calculate_debt_future_value(self, debt_id):
        try:
            debts = self.db_manager.get_debts(self.user_account.user_id)
            debt = next((d for d in debts if d[0] == debt_id), None)
            if not debt:
                raise ValueError("Debt not found.")
            _, _, debt_name, principal, annual_rate, years, _ = debt
            rate_per_period = annual_rate / 100 / 12  # monthly rate
            total_periods = years * 12
            future_value = principal * ((1 + rate_per_period) ** total_periods)
            print(f"Future value of debt '{debt_name}' after {years} years: {future_value:.2f}")
        except ValueError as e:
            print(f"Error: {e}")

    def check_due_debts(self):
        debts = self.db_manager.get_debts(self.user_account.user_id)
        if not debts:
            return
        today = datetime.now().date()
        upcoming = []
        overdue = []
        for debt in debts:
            _, _, debt_name, amount, annual_rate, years, due_date_str = debt
            due_date = datetime.fromisoformat(due_date_str).date()
            if due_date < today:
                overdue.append((debt_name, due_date))
            elif due_date <= today + timedelta(days=7):
                upcoming.append((debt_name, due_date))
        if overdue:
            print("\n⚠️ The following debts are overdue:")
            for debt_name, due_date in overdue:
                print(f"- {debt_name}, Due Date: {due_date}")
        if upcoming:
            print("\n🔔 The following debts are due within a week:")
            for debt_name, due_date in upcoming:
                print(f"- {debt_name}, Due Date: {due_date}")


# ========== Expense Categorization ==========
class ExpenseCategorization:
    def __init__(self):
        self.expenses = {}

    def categorize_expense(self, category, amount):
        try:
            if amount <= 0:
                raise ValueError("Expense amount must be positive")
            if category not in self.expenses:
                self.expenses[category] = 0
            self.expenses[category] += amount
            print(f"Added expense {amount:.2f} to category '{category}'. Total for this category: {self.expenses[category]:.2f}")
        except ValueError as e:
            print(f"Error: {e}")

    def get_expense_report(self):
        if not self.expenses:
            print("No expenses recorded.")
            return
        print("\n--- Expense Report ---")
        for category, amount in self.expenses.items():
            print(f"{category}: {amount:.2f}")


# ========== Savings Calculator (with compound interest) ==========
class SavingsCalculator:
    def __init__(self, user_account):
        self.user_account = user_account

    def calculate_savings_potential(self, target_savings, months):
        try:
            if target_savings <= 0 or months <= 0:
                raise ValueError("Target savings must be positive and months must be greater than zero")
            monthly_savings = target_savings / months
            return monthly_savings
        except ValueError as e:
            print(f"Error: {e}")

    def suggest_savings_plan(self, target_savings, months):
        try:
            monthly_savings = self.calculate_savings_potential(target_savings, months)
            if monthly_savings is None:
                return
            current_balance = self.user_account.get_balance()
            if current_balance >= target_savings:
                return "Your savings goal is already met."
            else:
                return f"Save {monthly_savings:.2f} per month for {months} months to reach your target."
        except ValueError as e:
            print(f"Error: {e}")

    def compound_savings(self, principal, annual_rate, years, compounding_periods=12):
        try:
            if principal < 0 or annual_rate < 0 or years < 0:
                raise ValueError("Invalid input for compound savings calculation")
            rate_per_period = annual_rate / compounding_periods
            total_periods = compounding_periods * years
            future_value = principal * ((1 + rate_per_period) ** total_periods)
            return future_value
        except ValueError as e:
            print(f"Error: {e}")


# ========== Data Visualization ==========
class DataVisualization:
    def __init__(self, db_manager, user_account):
        self.db_manager = db_manager
        self.user_account = user_account

    def plot_balance_over_time(self):
        records = self.db_manager.get_transactions(self.user_account.user_id)
        if not records:
            print("No transactions to display.")
            return

        balances = []
        timestamps = []

        # Get all transaction records and sort by time
        sorted_records = sorted(records, key=lambda x: x[4])  # x[4] is timestamp

        # Assume the initial balance is current balance minus all transaction amounts
        initial_balance = self.user_account.balance
        for record in sorted_records:
            initial_balance -= record[2]  # amount
        current_balance = initial_balance

        for record in sorted_records:
            current_balance += record[2]  # amount
            balances.append(current_balance)
            timestamps.append(record[4])

        if not balances:
            print("No transactions to plot.")
            return

        timestamps = [datetime.fromisoformat(ts) for ts in timestamps]

        plt.figure(figsize=(10, 5))
        plt.plot(timestamps, balances, marker='o')
        plt.title("Account Balance Over Time")
        plt.xlabel("Time")
        plt.ylabel("Balance")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()


# ========== Auto Financial Advisor ==========
class AutoFinancialAdvisor:
    def __init__(self, user_account):
        self.user_account = user_account

    def give_advice(self):
        balance = self.user_account.get_balance()
        if balance > 5000:
            return "You are in a great financial position! Consider investing."
        elif balance > 1000:
            return "Your finances are stable, but consider saving more."
        else:
            return "It’s time to be cautious with spending. Focus on building savings."


# ========== Main Function Demonstration ==========
def main():
    db_manager = DatabaseManager()

    while True:
        print("\nWelcome to the Banking System")
        print("1. Log In")
        print("2. Register")
        print("3. Exit")
        choice = input("Select an option (1-3): ").strip()

        if choice == '1':
            email = input("Enter your email: ").strip()
            password = input("Enter your password: ").strip()
            try:
                user = UserAccount.load_from_db(db_manager, email, password)
                print("Login successful.")
                break
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == '2':
            name = input("Enter your name: ").strip()
            email = input("Enter your email: ").strip()
            print("Password must be at least 6 characters long and contain at least one letter and one digit.")
            password = input("Enter your password: ").strip()
            phone = input("Enter your phone number: ").strip()
            try:
                user = UserAccount(db_manager, name=name, email=email, password=password, phone=phone, balance=0)
                print("User registered successfully.")
                break
            except ValueError as e:
                print(f"Error creating user: {e}")
        elif choice == '3':
            db_manager.close()
            print("Goodbye!")
            return
        else:
            print("Invalid choice. Please select a valid option.")

    # Initialize other managers
    tm = TransactionManager(db_manager, user)
    advisor = AutoFinancialAdvisor(user)
    sc = SavingsCalculator(user)
    viz = DataVisualization(db_manager, user)
    budget_manager = BudgetManager(db_manager, user)
    expense_categorizer = ExpenseCategorization()
    debt_manager = DebtManager(db_manager, user)

    # Check and remind debt repayment
    debt_manager.check_due_debts()

    while True:
        print("\n--- Banking System Menu ---")
        print("1. Deposit")
        print("2. Withdraw")
        print("3. Transfer")
        print("4. View Transaction History")
        print("5. Set Budget")
        print("6. View Expense Report")
        print("7. Add Expense")
        print("8. Savings Plan")
        print("9. View Financial Advice")
        print("10. View Balance Over Time")
        print("11. Update Personal Information")
        print("12. Manage Debts")
        print("13. Exit")
        print("14. View Current Balance")

        choice = input("Select an option (1-14): ").strip()

        if choice == '1':
            try:
                amount = float(input("Enter deposit amount: "))
                tm.add_income(amount)
            except ValueError:
                print("Invalid amount. Please enter a numeric value.")
        elif choice == '2':
            try:
                amount = float(input("Enter withdrawal amount: "))
                tm.add_expense(amount)
            except ValueError:
                print("Invalid amount. Please enter a numeric value.")
        elif choice == '3':
            recipient_email = input("Enter recipient's email: ").strip()
            recipient_data = db_manager.get_user_by_email(recipient_email)
            if not recipient_data:
                 print("Recipient not found.")
                 continue

            # Changed to verify the current user's password
            print("To verify your identity, please enter your password:")
            current_user_password = input("Enter your password: ").strip()
            current_user_hash = UserAccount.hash_password(current_user_password)
            if current_user_hash != user.password_hash:
                print("Incorrect password. Transfer aborted.")
                continue

            recipient = UserAccount(db_manager, user_id=recipient_data[0])
            try:
                amount = float(input("Enter transfer amount: "))
                tm.transfer(recipient, amount)
            except ValueError:
                print("Invalid amount. Please enter a numeric value.")
        elif choice == '4':
            tm.get_transaction_history()
        elif choice == '5':
            category = input("Enter budget category: ").strip()
            try:
                amount = float(input("Enter budget amount: "))
                budget_manager.set_budget(category, amount)
            except ValueError:
                print("Invalid amount. Please enter a numeric value.")
        elif choice == '6':
            expense_categorizer.get_expense_report()
        elif choice == '7':
            category = input("Enter expense category: ").strip()
            try:
                amount = float(input("Enter expense amount: "))
                expense_categorizer.categorize_expense(category, amount)
            except ValueError:
                print("Invalid amount. Please enter a numeric value.")
        elif choice == '8':
            try:
                target = float(input("Enter target savings: "))
                months = int(input("Enter number of months: "))
                plan = sc.suggest_savings_plan(target, months)
                if plan:
                    print(plan)
                # Calculate compound savings example
                future_value = sc.compound_savings(user.balance, 0.05, 5)  # Example: 5% interest rate over 5 years
                if future_value is not None:
                    print(f"Future value of your current savings after 5 years: {future_value:.2f}")
            except ValueError:
                print("Invalid input. Please enter numeric values.")
        elif choice == '9':
            advice = advisor.give_advice()
            print(advice)
        elif choice == '10':
            viz.plot_balance_over_time()
        elif choice == '11':
            print("\nUpdate Personal Information:")
            name = input("Enter new name (leave blank to keep current): ").strip()
            email_new = input("Enter new email (leave blank to keep current): ").strip()
            password = input("Enter new password (leave blank to keep current): ").strip()
            phone = input("Enter new phone number (leave blank to keep current): ").strip()
            daily_limit = input("Enter new daily limit (leave blank to keep current): ").strip()
            loan_total = input("Enter new loan total (leave blank to keep current): ").strip()

            try:
                daily_limit = float(daily_limit) if daily_limit else None
            except ValueError:
                print("Invalid daily limit. It must be a numeric value.")
                daily_limit = None
            try:
                loan_total = float(loan_total) if loan_total else None
            except ValueError:
                print("Invalid loan total. It must be a numeric value.")
                loan_total = None

            user.update_personal_info(
                name=name if name else None,
                email=email_new if email_new else None,
                password=password if password else None,
                phone=phone if phone else None,
                daily_limit=daily_limit,
                loan_total=loan_total
            )
        elif choice == '12':
            while True:
                print("\n--- Debt Management Menu ---")
                print("1. Add Debt")
                print("2. Pay Debt")
                print("3. View Debts")
                print("4. Calculate Debt Future Value")
                print("5. Back to Main Menu")

                debt_choice = input("Select an option (1-5): ").strip()

                if debt_choice == '1':
                    debt_name = input("Enter debt name: ").strip()
                    try:
                        amount = float(input("Enter debt amount: "))
                        annual_rate = float(input("Enter annual interest rate (in %): "))
                        years = int(input("Enter loan period in years: "))
                        debt_manager.add_debt(debt_name, amount, annual_rate, years)
                        debt_manager.check_due_debts()
                    except ValueError:
                        print("Invalid input. Please enter numeric values.")
                elif debt_choice == '2':
                    try:
                        debt_id = int(input("Enter debt ID to pay: "))
                        amount = float(input("Enter payment amount: "))
                        debt_manager.pay_debt(debt_id, amount)
                        debt_manager.check_due_debts()
                    except ValueError:
                        print("Invalid input. Please enter numeric values.")
                elif debt_choice == '3':
                    debt_manager.view_debts()
                elif debt_choice == '4':
                    try:
                        debt_id = int(input("Enter debt ID to calculate future value: "))
                        debt_manager.calculate_debt_future_value(debt_id)
                    except ValueError:
                        print("Invalid input. Please enter numeric values.")
                elif debt_choice == '5':
                    break
                else:
                    print("Invalid choice. Please select a valid option.")
        elif choice == '14':
            print(f"Your current balance is: {user.get_balance():.2f}")
        elif choice == '13':
            print("Exiting the system. Goodbye!")
            db_manager.close()
            break
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()
