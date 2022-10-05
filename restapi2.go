package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name     string `json:"name" form:"name"`
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
	Hp       string `json:"hp" form:"hp"`
}

type Vendor struct {
	gorm.Model
	Name_co   string `json:"name_co" form:"name_co"`
	Expedisi  string `json:"expedisi" form:"expedisi"`
	Transport string `json:"transport" form:"transport"`
	// Time_go   time.Time
	// Time_come time.Time
	Is_done bool
}

func connectDBGorm() *gorm.DB {
	dsn := "root:@tcp(127.0.0.1:3306)/restapi_db?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	return db
}

func GenerateToken(id uint) string {
	claim := make(jwt.MapClaims)
	claim["autorized"] = true
	claim["id"] = id
	claim["exp"] = time.Now().Add(time.Hour * 1).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	str, err := token.SignedString([]byte("kh@k1m"))
	if err != nil {
		log.Error(err.Error())
		return ""
	}
	return str
}

func Regist(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user User
		if err := c.Bind(&user); err != nil {
			log.Error(err)
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": "cannot read data",
			})
		}
		Pass, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost) //dycrypt password
		user.Password = string(Pass)
		newuser := User{
			Name:     user.Name,
			Email:    user.Email,
			Password: user.Password,
			Hp:       user.Hp,
		}

		if err := db.Create(&newuser).Error; err != nil {
			log.Error(err.Error())
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"message": "cannot insert data",
			})
		}

		return c.JSON(http.StatusCreated, map[string]interface{}{
			"message": "success insert new user",
			"data":    newuser,
		})
	}
}

func Login(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// email := c.Param("email")
		//var Password string
		var resQry User
		if err := c.Bind(&resQry); err != nil {
			log.Error(err.Error())
			c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": "cant proces data",
			})
		}

		//check email
		if err := db.First(&resQry, "email = ? and hp =?", resQry.Email, resQry.Hp).Error; err != nil {
			log.Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"message": "wrong email ",
			})
		}

		resToken := GenerateToken(resQry.ID)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "success get specific data",
			"data":    resQry,
			"token":   resToken,
		})
	}
}

func GetAllvendor(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var ven []Vendor
		if err := db.Find(&ven).Error; err != nil {
			log.Error(err.Error())
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"message": "error on database",
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "success get all data",
			"data":    ven,
		})
	}
}

func GetDataVendor(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		expedisi := c.Param("expedisi")

		var ven []Vendor
		if err := db.First(&ven, "expedisi = ?", expedisi).Error; err != nil {
			log.Error(err.Error())
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"message": "cannot select data",
			})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "success get specific data",
			"data":    ven,
		})
	}
}

func AddVendor(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var newven Vendor

		if err := c.Bind(&newven); err != nil {
			log.Error(err)
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"message": "cannot read data",
			})
		}
		if err := db.Create(&newven).Error; err != nil {
			log.Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"message": "cannot insert data",
			})
		}
		return c.JSON(http.StatusCreated, map[string]interface{}{
			"message": "success insert new user",
			"data":    newven,
		})
	}
}

func migrate(db *gorm.DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Vendor{})

}

func main() {
	e := echo.New()
	db := connectDBGorm()
	migrate(db)

	e.Use(middleware.Logger())
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.CORS())

	e.POST("/users", Regist(db))
	e.POST("/login", Login(db))
	e.GET("/vendors", GetAllvendor(db))
	e.GET("/vendors/:expedisi", GetDataVendor(db), middleware.BasicAuth(func(name, hp string, ctx echo.Context) (bool, error) {
		user := User{}
		if err := db.First(&user, "name =? and hp = ?", name, hp); err.Error != nil {
			log.Error(user)
			return false, err.Error
		}
		return true, nil
	}))
	e.POST("/vendors", AddVendor(db), middleware.JWT([]byte("kh@k1m")))

	e.Start(":8000") //echo mulai

}
