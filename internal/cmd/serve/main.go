package serve

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/snapp-incubator/soteria/internal/api"
	"github.com/snapp-incubator/soteria/internal/authenticator"
	"github.com/snapp-incubator/soteria/internal/config"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Serve struct {
	Cfg    config.Config
	Logger *zap.Logger
	Tracer trace.Tracer
}

func (s Serve) main() {
	auth, err := authenticator.Builder{
		Vendors:                    s.Cfg.Vendors,
		Logger:                     s.Logger,
		ValidatorConfig:            s.Cfg.Validator,
		Tracer:                     s.Tracer,
		BlackListUserLoggingConfig: s.Cfg.BlackListUserLogging,
	}.Authenticators()
	if err != nil {
		s.Logger.Fatal("authenticator building failed", zap.Error(err))
	}

	api := api.API{
		DefaultVendor:  s.Cfg.DefaultVendor,
		Authenticators: auth,
		Tracer:         s.Tracer,
		Logger:         s.Logger.Named("api"),
	}

	if _, ok := api.Authenticators[s.Cfg.DefaultVendor]; !ok {
		s.Logger.Fatal("default vendor shouldn't be nil, please set it")
	}

	rest := api.ReSTServer()

	go func() {
		if err := rest.Listen(fmt.Sprintf(":%d", s.Cfg.HTTPPort)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logger.Fatal("failed to run REST HTTP server", zap.Error(err))
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	if err := rest.Shutdown(); err != nil {
		s.Logger.Error("error happened during REST API shutdown", zap.Error(err))
	}
}

// Register serve command.
func (s Serve) Register(root *cobra.Command) {
	root.AddCommand(
		//nolint: exhaustruct
		&cobra.Command{
			Use:   "serve",
			Short: "serve runs the application",
			Long:  `serve will run Soteria ReST server and waits until user disrupts.`,
			Run: func(_ *cobra.Command, _ []string) {
				s.main()
			},
		},
	)
}
