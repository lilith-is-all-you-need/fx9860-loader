#include <gint/gint.h>
#include <gint/keyboard.h>

#include <fxlibc/printf.h>

#include "giac_port.h"
#include "ui.h"
#include "map_api.h"
#if KHICAS_UI_PLOTS
#include "plot_view.h"
#endif

#if KHICAS_UI_CAS
#include <gint/drivers/keydev.h>

#if defined(__sh__) && KHICAS_UI_COMPACT
#include <gint/hardware.h>
#endif

static bool cancelled;

/* Keys typed during evaluation belong to the busy screen. In particular,
   EXIT must not reach the editor and exit the add-in after cancellation. */
static int poll_cancel(void)
{
	keydev_t *keyboard = keydev_std();
	key_event_t event;
	while((event = keydev_read(keyboard, false, NULL)).type != KEYEV_NONE) {
		if(event.type == KEYEV_DOWN && event.key == KEY_EXIT)
			cancelled = true;
	}
	return cancelled;
}
#endif

static const char *evaluation_error(int status, const char *error)
{
	if(!KHICAS_UI_CAS && status == GIAC_PORT_UNSUPPORTED)
		return "CAS command unavailable";
	if(*error) return error;
	switch(status) {
	case GIAC_PORT_EMPTY: return "empty input";
	case GIAC_PORT_TOO_LONG: return "Input too long";
	case GIAC_PORT_RESULT_TOO_LONG: return "Result too long";
	case GIAC_PORT_CANCELLED: return "Cancelled";
	case GIAC_PORT_TIMEOUT: return "Time limit reached";
	case GIAC_PORT_OOM: return "Out of memory";
	case GIAC_PORT_UNSUPPORTED: return "CAS command unavailable";
	default: return "CAS evaluation failed";
	}
}

#if KHICAS_UI_PLOTS
static bool draw_plot(ui_state_t *ui, plot_view_t *view, bool fit, char *error)
{
	cancelled = false;
	*error = '\0';
	int status = GIAC_PORT_OK;
	if(fit) {
		ui->notice = "Drawing plot\nEXIT cancel";
		ui_draw(ui);
		status = plot_view_fit(view, giac_port_walk_plot, NULL, error, UI_ERROR_CAP);
	}
	if(!status)
		status = plot_view_draw(view, giac_port_walk_plot, NULL, error, UI_ERROR_CAP);
	if(poll_cancel() && !status)
		status = GIAC_PORT_CANCELLED;
	ui->notice = NULL;
	if(!status) return true;
	ui->notice = status == GIAC_PORT_CANCELLED ? "Plot cancelled" :
		(*error ? error : "Plot could not be displayed");
	return false;
}
#endif

int main(void)
{
	ui_state_t ui;
	char result[UI_RESULT_CAP];
	char error[UI_ERROR_CAP];
	int status;
#if KHICAS_UI_PLOTS
	plot_view_t plot;
#endif
	/* Consume physical modifier presses to render the pending state. The
	   shell routes MENU and OFF after resolving its own Shift latch. */
	const int key_options = GETKEY_DEFAULT & ~(GETKEY_MOD_SHIFT |
		GETKEY_MOD_ALPHA | GETKEY_MENU | GETKEY_POWEROFF);

	/* All three exit actions finish the CAS session and return through the
	   resident loader. No live external-code session remains in the menu. */
	gint_setrestart(0);
	khicas_map_request(KHICAS_MAP_EXIT);
	__printf_enable_fp();
	ui_init(&ui);
#if defined(__sh__) && KHICAS_UI_COMPACT
	/* gint groups several SH4 fx-9860G models under the same IDs. */
	if(isSH3() || (gint[HWCALC] != HWCALC_FX9860G_SH4 &&
		gint[HWCALC] != HWCALC_G35PE2)) {
		ui.notice = "Requires fx-9860GIII\nPress any key";
		ui_draw(&ui);
		getkey_opt(key_options, NULL);
		return 1;
	}
#endif
#if KHICAS_UI_CAS
	ui.notice = "Starting CAS";
	ui_draw(&ui);
	giac_port_set_cancel_poll(poll_cancel);
	error[0] = '\0';
	status = giac_port_init(error, sizeof error);
	ui.notice = NULL;
	if(status != GIAC_PORT_OK)
		ui_set_output(&ui, *error ? error : "CAS startup failed", true);
#endif
	ui_draw(&ui);

	for(;;) {
		key_event_t ev = getkey_opt(key_options, NULL);
		ui_action_t action = ui_handle_event(&ui, ev);
#if KHICAS_UI_PLOTS
		bool fit_plot = false, redraw_plot = false;
#endif
		switch(action) {
		case UI_EXIT:
			khicas_map_request(KHICAS_MAP_EXIT);
#if KHICAS_UI_CAS
			giac_port_shutdown();
#endif
			return 1;
		case UI_SYSTEM_MENU:
			khicas_map_request(KHICAS_MAP_MENU);
#if KHICAS_UI_CAS
			giac_port_shutdown();
#endif
			return 1;
		case UI_POWER_OFF:
			khicas_map_request(KHICAS_MAP_OFF);
#if KHICAS_UI_CAS
			giac_port_shutdown();
#endif
			return 1;
		case UI_EVAL:
			result[0] = '\0';
			error[0] = '\0';
#if KHICAS_UI_CAS
			cancelled = false;
			ui.notice = "Calculating\nEXIT cancel";
			ui_draw(&ui);
#endif
			status = giac_port_eval(ui.input, result, sizeof result,
				error, sizeof error);
#if KHICAS_UI_CAS
			poll_cancel();
			ui.notice = NULL;
#endif
			if(status == GIAC_PORT_OK) {
				ui_set_output(&ui, *result ? result : "Done", false);
#if KHICAS_UI_PLOTS
				ui.plot_available = giac_port_has_plot();
				fit_plot = ui.plot_open = ui.plot_available;
#endif
			} else {
				ui_set_output(&ui, evaluation_error(status, error), true);
			}
			break;
#if KHICAS_UI_PLOTS
		case UI_OPEN_PLOT:
			fit_plot = ui.plot_open = true;
			break;
		case UI_CLOSE_PLOT:
			ui.plot_open = false;
			break;
		case UI_PLOT_KEY:
			redraw_plot = plot_view_handle_key(&plot, ev.key);
			break;
#endif
#if KHICAS_UI_CAS
		case UI_RESET_CAS:
			error[0] = '\0';
			status = giac_port_reset(error, sizeof error);
			if(status == GIAC_PORT_OK) {
				ui.notice = "Variables reset";
#if KHICAS_UI_PLOTS
				ui.plot_available = false;
#endif
			} else {
				ui_set_output(&ui, *error ? error : "CAS reset failed", true);
			}
			break;
#endif
		default:
			break;
		}
#if KHICAS_UI_PLOTS
		if(ui.plot_open && (fit_plot || redraw_plot))
			ui.plot_open = draw_plot(&ui, &plot, fit_plot, error);
		if(ui.plot_open) continue;
#endif
		ui_draw(&ui);
	}
}
