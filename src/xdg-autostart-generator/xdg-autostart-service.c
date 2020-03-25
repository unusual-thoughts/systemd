/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "xdg-autostart-service.h"

#include "conf-parser.h"
#include "escape.h"
#include "unit-name.h"
#include "path-util.h"
#include "fd-util.h"
#include "generator.h"
#include "log.h"
#include "specifier.h"
#include "string-util.h"
#include "nulstr-util.h"
#include "strv.h"

void xdg_autostart_service_free(XdgAutostartService *s) {
        if (!s)
                return;

        free(s->name);
        free(s->path);
        free(s->description);

        free(s->type);
        free(s->exec_string);

        strv_free(s->only_show_in);
        strv_free(s->not_show_in);

        free(s->try_exec);
        free(s->autostart_condition);
        free(s->kde_autostart_condition);

        free(s->gnome_autostart_phase);

        free(s);
}

char *xdg_autostart_service_translate_name(const char *name) {
        _cleanup_free_ char *c = NULL;
        _cleanup_free_ char *escaped = NULL;
        char *res;

        c = strdup(name);
        if (!c)
                return NULL;

        res = endswith(c, ".desktop");
        if (res)
                *res = '\0';

        escaped = unit_name_escape(c);
        if (!escaped)
                return NULL;

        asprintf(&res, "apps-%s-autostart.service", escaped);

        return res;
}

static int xdg_config_parse_bool(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        bool *b = data;
        const char *value;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        value = skip_leading_chars(rvalue, NULL);
        if (streq(value, "true"))
                *b = 1;
        else if (streq(value, "false"))
                *b = 0;
        else {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid value for boolean: %s", value);
                return 0;
        }

        return 0;
}

/* Unescapes the string in-place, returns non-zero status on error. */
static int xdg_unescape_string(
                const char *unit,
                const char *filename,
                int line,
                char *str) {

        char *in;
        char *out;

        assert(str);

        in = out = str;

        for (; *in; in++, out++) {
                if (*in == '\\') {
                        /* Move forward, and ensure it is a valid escape. */
                        in++;

                        switch (*in) {
                                case 's':
                                        *out = ' ';
                                        break;
                                case 'n':
                                        *out = '\n';
                                        break;
                                case 't':
                                        *out = '\t';
                                        break;
                                case 'r':
                                        *out = '\r';
                                        break;
                                case '\\':
                                        *out = '\\';
                                        break;
                                case ';':
                                        /* Technically only permitted for strv. */
                                        *out = ';';
                                        break;
                                default:
                                        log_syntax(unit, LOG_ERR, filename, line, 0, "Undefined escape sequence \\%c.", *in);
                                        return -EINVAL;
                        }

                        continue;
                }

                *out = *in;
        }
        *out = '\0';

        return 0;
}

/* Note: We do not bother with unescaping the strings, hence the _raw postfix. */
static int xdg_config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* XDG does not allow duplicate definitions. */
        if (*s) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Key %s was defined multiple times, ignoring.", lvalue);
                return 0;
        }

        *s = strdup(skip_leading_chars(rvalue, NULL));
        if (*s == NULL)
                return log_oom();

        return xdg_unescape_string(unit, filename, line, *s);
}

static int xdg_config_parse_strv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = data;
        char *start;
        char *end;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* XDG does not allow duplicate definitions. */
        if (*sv) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Key %s was defined multiple times, ignoring.", lvalue);
                return 0;
        }

        *sv = strv_new(NULL);
        if (*sv == NULL)
                return log_oom();

        /* We cannot use strv_split because it does not handle escaping correctly. */
        start = skip_leading_chars(rvalue, NULL);

        for (end = start; *end; end++) {
                if (*end == '\\') {
                        /* Move forward, and ensure it is a valid escape. */
                        end++;
                        if (strchr("sntr\\;", *end) == NULL) {
                                log_syntax(unit, LOG_ERR, filename, line, 0, "Undefined escape sequence \\%c.", *end);
                                return 0;
                        }
                        continue;
                }

                if (*end == ';') {
                        _cleanup_free_ char *copy = NULL;

                        copy = strndup(start, end - start);
                        if (copy == NULL)
                                return log_oom();
                        r = xdg_unescape_string(unit, filename, line, copy);
                        if (r < 0)
                                return r;
                        r = strv_consume(sv, copy);
                        if (r < 0)
                                return r;
                        copy = NULL;

                        start = end + 1;
                }
        }

        /* Any trailing entry should be ignored if it is empty. */
        if (end > start) {
                r = strv_extend (sv, start);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int config_item_xdg_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata)
{
        XdgAutostartService *service = userdata;
        _cleanup_free_ char *lvalue_stripped = NULL;

        assert(table == NULL);
        assert(lvalue);
        assert(func);
        assert(ltype);
        assert(data);

        if (!streq_ptr(section, "Desktop Entry"))
                return 0;

        /* Space before and after the = sign should be ignored. */
        lvalue_stripped = delete_trailing_chars(strdup(lvalue), NULL);

        /* We don't need to handle any localised fields. */
        if (streq(lvalue_stripped, "Name")) {
                *func = xdg_config_parse_string;
                *data = &service->description;
        } else if (streq(lvalue_stripped, "Exec")) {
                *func = xdg_config_parse_string;
                *data = &service->exec_string;
        } else if (streq(lvalue_stripped, "TryExec")) {
                *func = xdg_config_parse_string;
                *data = &service->try_exec;
        } else if (streq(lvalue_stripped, "Type")) {
                *func = xdg_config_parse_string;
                *data = &service->type;
        } else if (streq(lvalue_stripped, "OnlyShowIn")) {
                *func = xdg_config_parse_strv;
                *data = &service->only_show_in;
        } else if (streq(lvalue_stripped, "NotShowIn")) {
                *func = xdg_config_parse_strv;
                *data = &service->not_show_in;
        } else if (streq(lvalue_stripped, "Hidden")) {
                *func = xdg_config_parse_bool;
                *data = &service->hidden;
        } else if (streq(lvalue_stripped, "AutostartCondition")) {
                *func = xdg_config_parse_string;
                *data = &service->autostart_condition;
        } else if (streq(lvalue_stripped, "X-KDE-autostart-condition")) {
                *func = xdg_config_parse_string;
                *data = &service->kde_autostart_condition;
        } else if (streq(lvalue_stripped, "X-GNOME-Autostart-Phase")) {
                *func = xdg_config_parse_string;
                *data = &service->gnome_autostart_phase;
        } else if (streq(lvalue_stripped, "X-GNOME-HiddenUnderSystemd")) {
                /* FIXME: X-systemd-skip? */
                *func = xdg_config_parse_bool;
                *data = &service->systemd_skip;
        }
        /* Parse Icon for %i? */

        return 1;
}

XdgAutostartService *xdg_autostart_service_parse_desktop(const char *path) {
        _cleanup_(xdg_autostart_service_freep) XdgAutostartService *service = NULL;
        int r;

        service = new0(XdgAutostartService, 1);
        if (!service)
                return NULL;

        service->path = strdup(path);

        r = config_parse(NULL, service->path, NULL,
                         "Desktop Entry\0",
                         config_item_xdg_lookup, NULL,
                         CONFIG_PARSE_WARN, service);
        /* If parsing failed, only hide the file so it will still mask others. */
        if (r < 0) {
                log_warning_errno(r, "failed to parse %s, ignoring it", service->path);
                service->hidden = 1;
        }

        return TAKE_PTR(service);
}

int xdg_autostart_format_exec_start(
                const char *exec,
                char **ret_exec_start) {

        _cleanup_strv_free_ char **exec_split = NULL;
        _cleanup_free_ char *exec_start = NULL;
        unsigned n, i;
        bool first_arg;
        int r;

        /*
         * Unfortunately, there is a mismatch between systemd's idea of $PATH
         * and XDGs. i.e. we need to ensure that we have an absolute path to
         * support cases where $PATH has been modified from the default set.
         *
         * Note that this is only needed for development environments though;
         * so while it is important, this should have no effect in production
         * environments.
         *
         * To be compliant with the XDG specification, we also need to strip
         * certain parameters and such. Doing so properly makes parsing the
         * command line unavoidable.
         *
         * NOTE: Technically, XDG only specifies " as quotes, while this also
         *       accepts '.
         */
        exec_split = strv_split_full(exec, WHITESPACE, SPLIT_QUOTES | SPLIT_RELAX);
        if (!exec_split)
                return -ENOMEM;

        if (strv_isempty (exec_split)) {
                log_info("Exec line is empty");
                return -EINVAL;
        }

        first_arg = 1;
        for (i = n = 0; exec_split[i]; i++) {
                _cleanup_free_ char *orig = NULL;
                _cleanup_free_ char *c = NULL;
                _cleanup_free_ char *raw = NULL;
                _cleanup_free_ char *p = NULL;
                _cleanup_free_ char *escaped = NULL;
                _cleanup_free_ char *quoted = NULL;

                orig = TAKE_PTR(exec_split[i]);
                r = cunescape(orig, 0, &c);
                if (r < 0) {
                        return log_debug_errno(r, "Failed to unescape '%s': %m", orig);
                }

                if (first_arg) {
                        _cleanup_free_ char *executable = NULL;

                        /* This is the executable, find it in $PATH */
                        first_arg = 0;
                        r = find_binary(c, &executable);
                        if (r < 0) {
                                return log_info_errno(r, "Exec binary '%s' does not exist: %m", c);
                        }

                        escaped = cescape(executable);
                        if (!escaped)
                                return log_oom();

                        exec_split[n++] = TAKE_PTR(escaped);
                        continue;
                }

                /*
                 * Remove any standardised XDG fields; we assume they never appear as
                 * part of another argument as that just does not make any sense as
                 * they can be empty (GLib will e.g. turn "%f" into an empty argument).
                 * Other implementations may handle this differently.
                 */
                if (STR_IN_SET(c,
                               "%f", "%F",
                               "%u", "%U",
                               "%d", "%D",
                               "%n", "%N",
                               "%i", /* Location of icon, could be implemented. */
                               "%c", /* Translated application name, could be implemented. */
                               "%k", /* Location of desktop file, could be implemented. */
                               "%v",
                               "%m"
                               ))
                        continue;

                /*
                 * %% -> % and then % -> %% means that we correctly quote any %
                 * and also quote any left over (and invalid) % specifier from
                 * the desktop file.
                 */
                raw = strreplace(c, "%%", "%");
                if (!raw)
                        return log_oom();
                p = strreplace(raw, "%", "%%");
                if (!p)
                        return log_oom();
                escaped = cescape(p);
                if (!escaped)
                        return log_oom();

                asprintf(&quoted, "\"%s\"", escaped);
                if (!quoted)
                        return log_oom();

                exec_split[n++] = TAKE_PTR(quoted);
        }

        *ret_exec_start = strv_join(exec_split, " ");

        return 0;
}

int xdg_autostart_service_generate_unit(
                XdgAutostartService *service,
                const char *dest) {

        _cleanup_free_ char *path_escaped = NULL;
        _cleanup_free_ char *exec_start = NULL;
        _cleanup_free_ char *condition_string = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *unit;
        int r;

        assert(service);

        /* Nothing to do for hidden services. */
        if (service->hidden) {
                log_info("Not generating service for XDG autostart %s, it is hidden", service->name);
                return 0;
        }

        if (service->systemd_skip) {
                log_info("Not generating service for XDG autostart %s, should be skipped by generator", service->name);
                return 0;
        }

        /* Nothing to do if type is not Application. */
        if (!streq_ptr(service->type, "Application")) {
                log_info("Not generating service for XDG autostart %s, it is hidden", service->name);
                return 0;
        }

        if (!service->exec) {
                log_info("Not generating service for XDG autostart %s, it is has no Exec= line", service->name);
                return 0;
        }

        /*
         * The TryExec key cannot be checked properly from the systemd unit,
         * it is trivial to check using find_binary though.
         */
        if (service->try_exec) {
                r = find_binary(service->try_exec, NULL);
                if (r < 0) {
                        log_info("Not generating service for XDG autostart %s, TryExec binary %s does not exist or not executable",
                                 service->name, service->try_exec);
                        return 0;
                }
        }

        r = xdg_autostart_format_exec_start(service->exec_string, &exec_start);
        if (r < 0) {
                log_info("Not generating service for XDG autostart %s, Exec line is invalid",
                         service->name);
                return 0;
        }

        if (streq_ptr(service->gnome_autostart_phase, "EarlyInitialization")) {
                log_info("Not generating service for XDG autostart %s, EarlyInitialization needs to be handled separately",
                         service->name);
                 return 0;
         }


        /* Partially handle AutostartCondition (as implemented by GNOME)
         *
         * Not implemented are:
         *  - GSettings (may be updated at runtime)
         *  - GNOME3 if-session/unless-session (which seems unused and undocumented)
         */
        if (service->autostart_condition) {
                const char *kind;
                const char *key;
                const char *state;
                size_t kind_length;
                _unused_ size_t key_length;

                /* Split into first word and rest (we don't use key_length). */
                state = service->autostart_condition;
                kind = split(&state, &kind_length, WHITESPACE, 0);
                key = split(&state, &key_length, WHITESPACE, 0);
                printf("kind: %p\n", kind);
                printf("key: %s\n", key);

                if (key && (strncaseeq("if-exists", kind, kind_length) || strncaseeq("unless-exists", kind, kind_length))) {
                        _cleanup_free_ char *e = NULL;

                        /* The key is a filename, just escape it. */
                        e = cescape(key);
                        asprintf(&condition_string,
                                 "ConditionPath=%s%%E/%s\n",
                                 strncaseeq("if-exists", kind, kind_length) ? "" : "!",
                                 e);
                        if (!condition_string)
                                return log_oom();
                } else {
                        /* Unsupported or something is wrong, we should never run this service */
                        log_warning("Not generating service for XDG autostart %s with unsupported AutostartCondition", service->name);
                        return 0;
                }
        }

        path_escaped = specifier_escape(service->path);
        if (!path_escaped)
                return log_oom();

        unit = prefix_roota(dest, service->name);

        f = fopen(unit, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create unit file %s: %m", unit);

        fprintf(f,
                "# Automatically generated by systemd-xdg-autostart-generator\n\n"
                "[Unit]\n"
                "Documentation=man:systemd-xdg-autostart-generator(8)\n"
                "SourcePath=%s\n"
                /* Disallow manual starting to make Conflicts= safer. */
                "RefuseManualStart=yes\n"
                "PartOf=graphical-session.target\n"
                "Requisite=xdg-desktop-autostart.target\n",
                path_escaped);

        if (service->description) {
                _cleanup_free_ char *t = NULL;

                t = specifier_escape(service->description);
                if (!t)
                        return log_oom();

                fprintf(f, "Description=%s\n", t);
        }

        if (condition_string)
                fprintf(f, "\n%s\n", condition_string);

        /* GNOME autostart phase emulation
         *
         * TODO: We will need to deal with other desktop environments to some
         *       extend for compatibility.
         * TODO: The targets here used with the GNOME logic need fixing. */
        if (STRPTR_IN_SET(service->gnome_autostart_phase,
                               "PreDisplayServer",
                               "DisplayServer",
                               "Initialization"))
                fprintf(f,
                        "After=graphical-session-pre.target\n"
                        "Before=xdg-desktop-autostart.target\n");
        else if (STRPTR_IN_SET(service->gnome_autostart_phase,
                               "WindowManager",
                               "Panel",
                               "Desktop"))
                fprintf(f,
                        "After=xdg-desktop-autostart.target\n"
                        "Before=graphical-session.target\n");
       else
                fprintf(f,
                        "After=graphical-session.target\n");

        fprintf(f,
                "\n[Service]\n"
                "Type=simple\n"
                "ExecStart=:%s\n"
                "Restart=no\n"
                "TimeoutSec=5sec\n"
                "Slice=apps.slice\n",
                exec_start);

        /* Generate an ExecCondition to check $XDG_CURRENT_DESKTOP */
        if (!strv_isempty(service->only_show_in) || !strv_isempty(service->not_show_in)) {
                _cleanup_free_ char *only_show_in = NULL;
                _cleanup_free_ char *not_show_in = NULL;
                _cleanup_free_ char *e_only_show_in = NULL;
                _cleanup_free_ char *e_not_show_in = NULL;

                only_show_in = strv_join(service->only_show_in, ":");
                not_show_in = strv_join(service->not_show_in, ":");
                if (!only_show_in || !not_show_in)
                        return log_oom();

                e_only_show_in = cescape(only_show_in);
                e_not_show_in = cescape(not_show_in);
                if (!e_only_show_in || !e_not_show_in)
                        return log_oom();

                /* Just assume the values are reasonably sane */
                fprintf(f,
                        "ExecCondition=" ROOTLIBEXECDIR "/systemd-xdg-autostart-condition \"%s\" \"%s\"\n",
                        e_only_show_in,
                        e_not_show_in);
        }

        (void) generator_add_symlink(dest, "xdg-desktop-autostart.target", "wants", service->name);

        return 0;
}
