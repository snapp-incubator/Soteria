package commands

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/patrickmn/go-cache"
	"github.com/spf13/cobra"
	snappids "gitlab.snapp.ir/dispatching/snappids/v2"
	"gitlab.snapp.ir/dispatching/soteria/configs"
	"gitlab.snapp.ir/dispatching/soteria/internal/accounts"
	"gitlab.snapp.ir/dispatching/soteria/internal/app"
	"gitlab.snapp.ir/dispatching/soteria/internal/authenticator"
	"gitlab.snapp.ir/dispatching/soteria/internal/db"
	"gitlab.snapp.ir/dispatching/soteria/internal/db/cachedredis"
	"gitlab.snapp.ir/dispatching/soteria/internal/db/redis"
	"gitlab.snapp.ir/dispatching/soteria/internal/factory"
	"gitlab.snapp.ir/dispatching/soteria/pkg"
	"gitlab.snapp.ir/dispatching/soteria/pkg/log"
	"gitlab.snapp.ir/dispatching/soteria/pkg/user"
	"gitlab.snapp.ir/dispatching/soteria/web/grpc"
	"gitlab.snapp.ir/dispatching/soteria/web/rest/api"
	"go.uber.org/zap"
	"net"
	"os"
	"os/signal"
)

var Serve = &cobra.Command{
	Use:    "serve",
	Short:  "serve runs the application",
	Long:   `serve will run Soteria REST and gRPC server and waits until user disrupts.`,
	PreRun: servePreRun,
	Run:    serveRun,
}

var cfg configs.AppConfig

func servePreRun(cmd *cobra.Command, args []string) {
	cfg = configs.InitConfig()
	log.InitLogger()
	log.SetLevel(cfg.Logger.Level)

	zap.L().Debug("config init successfully",
		zap.String("cache_config", pkg.PrettifyStruct(cfg.Cache)),
		zap.String("redis_config", pkg.PrettifyStruct(cfg.Redis)),
		zap.String("logger_config", pkg.PrettifyStruct(cfg.Logger)),
		zap.String("jwt_keys_path", cfg.Jwt.KeysPath),
		zap.String("allowed_access_types", fmt.Sprintf("%v", cfg.AllowedAccessTypes)))

	pk, err := cfg.ReadPrivateKey(user.ThirdParty)
	if err != nil {
		zap.L().Fatal("could not read third party private key")
	}

	hid := &snappids.HashIDSManager{
		Salts: map[snappids.Audience]string{
			snappids.DriverAudience:    cfg.DriverSalt,
			snappids.PassengerAudience: cfg.PassengerSalt,
		},
		Lengths: map[snappids.Audience]int{
			snappids.DriverAudience:    cfg.DriverHashLength,
			snappids.PassengerAudience: cfg.PassengerHashLength,
		},
	}

	rClient, err := redis.NewRedisClient(cfg.Redis)
	if err != nil {
		zap.L().Fatal("could not create redis client", zap.Error(err))
	}

	redisModelHandler := &redis.ModelHandler{Client: rClient}
	var modelHandler db.ModelHandler

	if cfg.Cache.Enabled {
		modelHandler = cachedredis.NewCachedRedisModelHandler(redisModelHandler, cache.New(cache.NoExpiration, cache.NoExpiration))
	} else {
		modelHandler = redisModelHandler
	}

	app.GetInstance().SetAccountsService(&accounts.Service{
		Handler: modelHandler,
	})

	allowedAccessTypes, err := cfg.GetAllowedAccessTypes()
	if err != nil {
		zap.L().Fatal("error while getting allowed access types", zap.Error(err))
	}
	app.GetInstance().SetAuthenticator(&authenticator.Authenticator{
		PrivateKeys: map[user.Issuer]*rsa.PrivateKey{
			user.ThirdParty: pk,
		},
		AllowedAccessTypes: allowedAccessTypes,
		ModelHandler:       modelHandler,
		HashIDSManager:     hid,
		EMQTopicManager:    snappids.NewEMQManager(hid),
	})

	app.GetInstance().SetMetrics(factory.GetMetrics("http"))
}

func serveRun(cmd *cobra.Command, args []string) {
	rest := api.RestServer(cfg.HttpPort)

	gListen, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GrpcPort))
	if err != nil {
		zap.L().Fatal("failed to listen", zap.Int("port", cfg.GrpcPort), zap.Error(err))
	}

	grpcServer := grpc.GRPCServer()

	go func() {
		if err := rest.ListenAndServe(); err != nil {
			zap.L().Fatal("failed to run REST HTTP server", zap.Error(err))
		}
	}()

	go func() {
		if err := grpcServer.Serve(gListen); err != nil {
			zap.L().Fatal("failed to run GRPC server", zap.Error(err))
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	if err := rest.Shutdown(context.Background()); err != nil {
		zap.L().Error("error happened during REST API shutdown", zap.Error(err))
	}

	grpcServer.Stop()
}
