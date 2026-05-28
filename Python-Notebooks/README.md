# Python Cryptographic Notebooks

A collection of Jupyter Notebooks implementing Russian GOST cryptographic standards and analyzing hash function vulnerabilities. 
Jupyter Notebooks are used here to provide step-by-step mathematical explanations alongside executable code.

## Notebooks Overview

*   **Streebog (GOST 34.11-2018):** Step-by-step implementation of the Streebog hash function ("Стрибог").
*   **Kuznyechik (GOST 34.12-2018):** Implementation of the Kuznyechik block cipher ("Кузнечик").
*   **GOST 34.10-2018:** Implementation of the asymmetric digital signature algorithm.
*   **MD5 Collision Search:** Practical analysis and search for MD5 hash collisions, demonstrating the vulnerability of outdated hash functions to birthday attacks.
*   **SP-Network (СПХ):** Implementation of a basic Substitution-Permutation Network, the foundational architecture for modern block ciphers.

## How to View and Run

**Viewing:** GitHub natively renders `.ipynb` files. Simply click on any notebook file in this directory to view the code, math, and outputs directly in your browser.

**Running Locally:**
If you want to execute the notebooks yourself:
1. Ensure you have Python and Jupyter installed:
``bash
pip install jupyter
``
2. Clone the repository and navigate to this folder.
3. Start the Jupyter server:
``bash
jupyter notebook
``
4. Open the desired `.ipynb` file from the browser interface.

## Focus Areas
*   **Pure Math Implementation:** Focusing on the bitwise operations and mathematical logic behind the standards.
*   **Visualization & Explanation:** Using Markdown cells in Jupyter to explain the "why" behind the code steps.
*   **Security Analysis:** Understanding why strong hash functions (Streebog) replace weak ones (MD5).
