import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip
import re
from typing import Dict, List

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.create_widgets()
        
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("🔐 Advanced Password Generator")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        # Set window icon and styling
        self.root.configure(bg='#f0f0f0')
        
        # Center the window on screen
        self.center_window()
        
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"600x700+{x}+{y}")
        
    def setup_variables(self):
        """Initialize all tkinter variables"""
        # Password options
        self.length_var = tk.IntVar(value=12)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.no_repeating = tk.BooleanVar(value=False)
        
        # Advanced options
        self.min_uppercase = tk.IntVar(value=1)
        self.min_lowercase = tk.IntVar(value=1)
        self.min_numbers = tk.IntVar(value=1)
        self.min_symbols = tk.IntVar(value=1)
        
        # Generated password
        self.password_var = tk.StringVar()
        
        # Character sets
        self.char_sets = {
            'uppercase': string.ascii_uppercase,
            'lowercase': string.ascii_lowercase,
            'numbers': string.digits,
            'symbols': "!@#$%^&*()_+-=[]{}|;:,.<>?"
        }
        
        # Ambiguous characters to exclude
        self.ambiguous_chars = "0O1lI|`"
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main title
        title_label = tk.Label(
            self.root,
            text="🔐 Advanced Password Generator",
            font=("Arial", 18, "bold"),
            bg='#f0f0f0',
            fg='#2c3e50'
        )
        title_label.pack(pady=20)
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(padx=20, pady=10, fill='both', expand=True)
        
        # Password length section
        self.create_length_section()
        
        # Character options section
        self.create_character_options()
        
        # Advanced options section
        self.create_advanced_options()
        
        # Generate button
        self.create_generate_section()
        
        # Password display and copy section
        self.create_password_display()
        
        # Password strength indicator
        self.create_strength_indicator()
        
        # Password history
        self.create_history_section()
        
    def create_length_section(self):
        """Create password length selection widgets"""
        length_frame = ttk.LabelFrame(self.main_frame, text="Password Length", padding=10)
        length_frame.pack(fill='x', pady=5)
        
        # Length slider
        length_label = ttk.Label(length_frame, text="Length:")
        length_label.grid(row=0, column=0, sticky='w', padx=5)
        
        self.length_scale = ttk.Scale(
            length_frame,
            from_=4,
            to=50,
            variable=self.length_var,
            orient='horizontal',
            command=self.update_length_label
        )
        self.length_scale.grid(row=0, column=1, sticky='ew', padx=10)
        
        self.length_display = ttk.Label(length_frame, text="12")
        self.length_display.grid(row=0, column=2, padx=5)
        
        length_frame.columnconfigure(1, weight=1)
        
    def create_character_options(self):
        """Create character set selection checkboxes"""
        char_frame = ttk.LabelFrame(self.main_frame, text="Character Sets", padding=10)
        char_frame.pack(fill='x', pady=5)
        
        # Character set checkboxes
        ttk.Checkbutton(
            char_frame,
            text="Uppercase Letters (A-Z)",
            variable=self.include_uppercase
        ).grid(row=0, column=0, sticky='w', pady=2)
        
        ttk.Checkbutton(
            char_frame,
            text="Lowercase Letters (a-z)",
            variable=self.include_lowercase
        ).grid(row=1, column=0, sticky='w', pady=2)
        
        ttk.Checkbutton(
            char_frame,
            text="Numbers (0-9)",
            variable=self.include_numbers
        ).grid(row=2, column=0, sticky='w', pady=2)
        
        ttk.Checkbutton(
            char_frame,
            text="Symbols (!@#$%^&*...)",
            variable=self.include_symbols
        ).grid(row=3, column=0, sticky='w', pady=2)
        
    def create_advanced_options(self):
        """Create advanced password options"""
        advanced_frame = ttk.LabelFrame(self.main_frame, text="Advanced Options", padding=10)
        advanced_frame.pack(fill='x', pady=5)
        
        # Exclude ambiguous characters
        ttk.Checkbutton(
            advanced_frame,
            text="Exclude ambiguous characters (0, O, 1, l, I, |)",
            variable=self.exclude_ambiguous
        ).grid(row=0, column=0, columnspan=2, sticky='w', pady=2)
        
        # No repeating characters
        ttk.Checkbutton(
            advanced_frame,
            text="No repeating characters",
            variable=self.no_repeating
        ).grid(row=1, column=0, columnspan=2, sticky='w', pady=2)
        
        # Minimum character requirements
        ttk.Label(advanced_frame, text="Minimum Requirements:").grid(row=2, column=0, columnspan=2, sticky='w', pady=(10,5))
        
        # Min uppercase
        ttk.Label(advanced_frame, text="Min Uppercase:").grid(row=3, column=0, sticky='w', padx=(20,5))
        ttk.Spinbox(
            advanced_frame,
            from_=0,
            to=10,
            width=5,
            textvariable=self.min_uppercase
        ).grid(row=3, column=1, sticky='w')
        
        # Min lowercase
        ttk.Label(advanced_frame, text="Min Lowercase:").grid(row=4, column=0, sticky='w', padx=(20,5))
        ttk.Spinbox(
            advanced_frame,
            from_=0,
            to=10,
            width=5,
            textvariable=self.min_lowercase
        ).grid(row=4, column=1, sticky='w')
        
        # Min numbers
        ttk.Label(advanced_frame, text="Min Numbers:").grid(row=5, column=0, sticky='w', padx=(20,5))
        ttk.Spinbox(
            advanced_frame,
            from_=0,
            to=10,
            width=5,
            textvariable=self.min_numbers
        ).grid(row=5, column=1, sticky='w')
        
        # Min symbols
        ttk.Label(advanced_frame, text="Min Symbols:").grid(row=6, column=0, sticky='w', padx=(20,5))
        ttk.Spinbox(
            advanced_frame,
            from_=0,
            to=10,
            width=5,
            textvariable=self.min_symbols
        ).grid(row=6, column=1, sticky='w')
        
    def create_generate_section(self):
        """Create password generation button"""
        generate_frame = ttk.Frame(self.main_frame)
        generate_frame.pack(fill='x', pady=15)
        
        self.generate_btn = ttk.Button(
            generate_frame,
            text="🎲 Generate Password",
            command=self.generate_password,
            style='Accent.TButton'
        )
        self.generate_btn.pack(expand=True)
        
    def create_password_display(self):
        """Create password display and copy functionality"""
        display_frame = ttk.LabelFrame(self.main_frame, text="Generated Password", padding=10)
        display_frame.pack(fill='x', pady=5)
        
        # Password display
        self.password_entry = ttk.Entry(
            display_frame,
            textvariable=self.password_var,
            font=("Courier", 12),
            state='readonly',
            width=50
        )
        self.password_entry.pack(side='left', expand=True, fill='x', padx=(0,10))
        
        # Copy button
        self.copy_btn = ttk.Button(
            display_frame,
            text="📋 Copy",
            command=self.copy_password,
            state='disabled'
        )
        self.copy_btn.pack(side='right')
        
    def create_strength_indicator(self):
        """Create password strength indicator"""
        strength_frame = ttk.LabelFrame(self.main_frame, text="Password Strength", padding=10)
        strength_frame.pack(fill='x', pady=5)
        
        self.strength_var = tk.StringVar(value="No password generated")
        self.strength_label = ttk.Label(
            strength_frame,
            textvariable=self.strength_var,
            font=("Arial", 10, "bold")
        )
        self.strength_label.pack()
        
        # Strength progress bar
        self.strength_progress = ttk.Progressbar(
            strength_frame,
            length=400,
            mode='determinate'
        )
        self.strength_progress.pack(pady=5)
        
    def create_history_section(self):
        """Create password history section"""
        history_frame = ttk.LabelFrame(self.main_frame, text="Recent Passwords", padding=10)
        history_frame.pack(fill='both', expand=True, pady=5)
        
        # History listbox with scrollbar
        history_container = ttk.Frame(history_frame)
        history_container.pack(fill='both', expand=True)
        
        self.history_listbox = tk.Listbox(
            history_container,
            font=("Courier", 10),
            height=6
        )
        self.history_listbox.pack(side='left', fill='both', expand=True)
        
        history_scrollbar = ttk.Scrollbar(history_container, orient='vertical')
        history_scrollbar.pack(side='right', fill='y')
        
        self.history_listbox.config(yscrollcommand=history_scrollbar.set)
        history_scrollbar.config(command=self.history_listbox.yview)
        
        # History buttons
        history_btn_frame = ttk.Frame(history_frame)
        history_btn_frame.pack(fill='x', pady=(10,0))
        
        ttk.Button(
            history_btn_frame,
            text="Copy Selected",
            command=self.copy_from_history
        ).pack(side='left', padx=(0,5))
        
        ttk.Button(
            history_btn_frame,
            text="Clear History",
            command=self.clear_history
        ).pack(side='left')
        
        # Initialize history list
        self.password_history = []
        
    def update_length_label(self, value):
        """Update length display label"""
        self.length_display.config(text=str(int(float(value))))
        
    def generate_password(self):
        """Generate a password based on selected criteria"""
        try:
            # Validate settings
            if not self.validate_settings():
                return
                
            # Get available characters
            available_chars = self.get_available_characters()
            
            if not available_chars:
                messagebox.showerror("Error", "Please select at least one character set!")
                return
                
            # Generate password
            password = self.create_password(available_chars)
            
            # Update UI
            self.password_var.set(password)
            self.copy_btn.config(state='normal')
            
            # Add to history
            self.add_to_history(password)
            
            # Update strength indicator
            self.update_strength_indicator(password)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
            
    def validate_settings(self) -> bool:
        """Validate password generation settings"""
        length = self.length_var.get()
        
        # Check if any character set is selected
        if not any([
            self.include_uppercase.get(),
            self.include_lowercase.get(),
            self.include_numbers.get(),
            self.include_symbols.get()
        ]):
            messagebox.showerror("Error", "Please select at least one character set!")
            return False
            
        # Check minimum requirements
        min_total = (self.min_uppercase.get() + self.min_lowercase.get() + 
                    self.min_numbers.get() + self.min_symbols.get())
        
        if min_total > length:
            messagebox.showerror(
                "Error", 
                f"Minimum character requirements ({min_total}) exceed password length ({length})!"
            )
            return False
            
        return True
        
    def get_available_characters(self) -> str:
        """Get available characters based on selected options"""
        chars = ""
        
        if self.include_uppercase.get():
            chars += self.char_sets['uppercase']
        if self.include_lowercase.get():
            chars += self.char_sets['lowercase']
        if self.include_numbers.get():
            chars += self.char_sets['numbers']
        if self.include_symbols.get():
            chars += self.char_sets['symbols']
            
        # Remove ambiguous characters if requested
        if self.exclude_ambiguous.get():
            chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            
        return chars
        
    def create_password(self, available_chars: str) -> str:
        """Create password with specified requirements"""
        length = self.length_var.get()
        password = []
        
        # Add minimum required characters
        if self.include_uppercase.get() and self.min_uppercase.get() > 0:
            uppercase_chars = [c for c in self.char_sets['uppercase'] if c in available_chars]
            password.extend(random.choices(uppercase_chars, k=self.min_uppercase.get()))
            
        if self.include_lowercase.get() and self.min_lowercase.get() > 0:
            lowercase_chars = [c for c in self.char_sets['lowercase'] if c in available_chars]
            password.extend(random.choices(lowercase_chars, k=self.min_lowercase.get()))
            
        if self.include_numbers.get() and self.min_numbers.get() > 0:
            number_chars = [c for c in self.char_sets['numbers'] if c in available_chars]
            password.extend(random.choices(number_chars, k=self.min_numbers.get()))
            
        if self.include_symbols.get() and self.min_symbols.get() > 0:
            symbol_chars = [c for c in self.char_sets['symbols'] if c in available_chars]
            password.extend(random.choices(symbol_chars, k=self.min_symbols.get()))
            
        # Fill remaining length
        remaining_length = length - len(password)
        
        if self.no_repeating.get():
            # Ensure no repeating characters
            available_for_remaining = [c for c in available_chars if c not in password]
            if len(available_for_remaining) < remaining_length:
                raise ValueError("Cannot generate password without repeating characters with current settings")
            password.extend(random.sample(available_for_remaining, remaining_length))
        else:
            password.extend(random.choices(available_chars, k=remaining_length))
            
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)
        
    def copy_password(self):
        """Copy generated password to clipboard"""
        try:
            password = self.password_var.get()
            if password:
                pyperclip.copy(password)
                messagebox.showinfo("Success", "Password copied to clipboard!")
            else:
                messagebox.showwarning("Warning", "No password to copy!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")
            
    def add_to_history(self, password: str):
        """Add password to history"""
        self.password_history.insert(0, password)
        
        # Keep only last 10 passwords
        if len(self.password_history) > 10:
            self.password_history = self.password_history[:10]
            
        # Update listbox
        self.history_listbox.delete(0, tk.END)
        for pwd in self.password_history:
            # Mask password for display (show first 3 and last 3 chars)
            if len(pwd) > 6:
                display_pwd = f"{pwd[:3]}{'*' * (len(pwd) - 6)}{pwd[-3:]}"
            else:
                display_pwd = '*' * len(pwd)
            self.history_listbox.insert(tk.END, f"{display_pwd} (Length: {len(pwd)})")
            
    def copy_from_history(self):
        """Copy selected password from history"""
        try:
            selection = self.history_listbox.curselection()
            if selection:
                index = selection[0]
                password = self.password_history[index]
                pyperclip.copy(password)
                messagebox.showinfo("Success", "Password copied from history!")
            else:
                messagebox.showwarning("Warning", "Please select a password from history!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy from history: {str(e)}")
            
    def clear_history(self):
        """Clear password history"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear password history?"):
            self.password_history.clear()
            self.history_listbox.delete(0, tk.END)
            
    def update_strength_indicator(self, password: str):
        """Update password strength indicator"""
        strength_score, strength_text, color = self.calculate_strength(password)
        
        self.strength_var.set(strength_text)
        self.strength_progress['value'] = strength_score
        
        # Update label color (note: limited color options in tkinter)
        if strength_score < 30:
            style_name = 'Weak.TLabel'
        elif strength_score < 60:
            style_name = 'Medium.TLabel'
        else:
            style_name = 'Strong.TLabel'
            
    def calculate_strength(self, password: str) -> tuple:
        """Calculate password strength score"""
        if not password:
            return 0, "No password", "gray"
            
        score = 0
        feedback = []
        
        # Length scoring
        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        else:
            feedback.append("Too short")
            
        # Character variety scoring
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        char_types = sum([has_upper, has_lower, has_digit, has_symbol])
        score += char_types * 15
        
        # Pattern checking
        if not re.search(r'(.)\1{2,}', password):  # No 3+ repeated chars
            score += 10
        else:
            feedback.append("Repeated characters")
            
        if not re.search(r'(abc|123|qwe)', password.lower()):  # No common sequences
            score += 10
        else:
            feedback.append("Common sequences")
            
        # Determine strength level
        if score >= 80:
            return min(score, 100), "Very Strong 💪", "green"
        elif score >= 60:
            return score, "Strong 🔒", "darkgreen"
        elif score >= 40:
            return score, "Medium ⚠️", "orange"
        elif score >= 20:
            return score, "Weak 🔓", "red"
        else:
            return score, "Very Weak ❌", "darkred"

def main():
    """Main function to run the password generator"""
    # Create main window
    root = tk.Tk()
    
    # Configure styles
    style = ttk.Style()
    style.theme_use('clam')
    
    # Create application
    app = PasswordGenerator(root)
    
    # Start GUI event loop
    root.mainloop()

if __name__ == "__main__":
    # Check if pyperclip is available
    try:
        import pyperclip
    except ImportError:
        print("Installing required dependency: pyperclip")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
        import pyperclip
    
    main()