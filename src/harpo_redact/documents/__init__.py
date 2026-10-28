"""Document redaction: PDF, Word, Excel, PowerPoint and text files.

Untrusted files are parsed in a separate worker process (``worker``); the gateway
process only ever sees extracted text and sends back edits. See ``service`` for the
flow and ``runner`` for the process boundary. This package's engine modules must not
import the gateway's pipeline, config or HTTP code: the worker loads only them.
"""
