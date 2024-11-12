package obj

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/config"
)

const (
	_testJSON = `
{
    "test":{
        "settings":{
            "int_key":1000,
            "float_key":1000.1,
            "duration_key":10000,
            "string_key":"string_value"
        },
        "server":{
            "addr":"127.0.0.1",
            "port":8000
        }
    },
    "foo":[
        {
            "name":"nihao",
            "age":18
        },
        {
            "name":"nihao",
            "age":18
        }
    ]
}`

	_testJSONUpdate = `
{
    "test":{
        "settings":{
            "int_key":1000,
            "float_key":1000.1,
            "duration_key":10000,
            "string_key":"string_value"
        },
        "server":{
            "addr":"127.0.0.1",
            "port":8000
        }
    },
    "foo":[
        {
            "name":"nihao",
            "age":18
        },
        {
            "name":"nihao",
            "age":18
        }
    ],
	"bar":{
		"event":"update"
	}
}`

	//	_testYaml = `
	//Foo:
	//    bar :
	//        - {name: nihao,age: 1}
	//        - {name: nihao,age: 1}
	//
	//
	//`
)

//func TestScan(t *testing.T) {
//
//}

type TestJSON struct {
	Test struct {
		Settings struct {
			IntKey      int     `json:"int_key"`
			FloatKey    float64 `json:"float_key"`
			DurationKey int     `json:"duration_key"`
			StringKey   string  `json:"string_key"`
		} `json:"settings"`
		Server struct {
			Addr string `json:"addr"`
			Port int    `json:"port"`
		} `json:"server"`
	} `json:"test"`
	Foo []struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	} `json:"foo"`
}

func TestFile(t *testing.T) {
	var (
		path = filepath.Join(t.TempDir(), "test_config")
		file = filepath.Join(path, "test.json")
		data = []byte(_testJSON)
	)
	defer os.Remove(path)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Error(err)
	}
	if err := os.WriteFile(file, data, 0o666); err != nil {
		t.Error(err)
	}
	testSource(t, file, data)
	testSource(t, path, data)
}

func testSource(t *testing.T, path string, data []byte) {
	t.Log(path)

	var source TestJSON
	err := json.Unmarshal(data, &source)
	if err != nil {
		t.Error(err)
	}

	s := NewSource(source)
	kvs, err := s.Load()
	if err != nil {
		t.Error(err)
	}
	var d1 TestJSON
	if err := json.Unmarshal(kvs[0].Value, &d1); err != nil {
		t.Error(err)
	}
	var d2 TestJSON
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(d1, d2) {
		t.Errorf("no expected: %+v, but got: %+v", d1, d2)
	}
}

func TestConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test_config.json")
	defer os.Remove(path)
	if err := os.WriteFile(path, []byte(_testJSON), 0o666); err != nil {
		t.Error(err)
	}
	type TestJSON struct {
		Test struct {
			Settings struct {
				IntKey      int     `json:"int_key"`
				FloatKey    float64 `json:"float_key"`
				DurationKey int     `json:"duration_key"`
				StringKey   string  `json:"string_key"`
			} `json:"settings"`
			Server struct {
				Addr string `json:"addr"`
				Port int    `json:"port"`
			} `json:"server"`
		} `json:"test"`
		Foo []struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		} `json:"foo"`
	}
	c := config.New(config.WithSource(
		NewSource(new(TestJSON)),
	))
	testScan(t, c)

	testConfig(t, c)
}

func testConfig(t *testing.T, c config.Config) {
	expected := map[string]interface{}{
		"test.settings.int_key":      int64(1000),
		"test.settings.float_key":    1000.1,
		"test.settings.string_key":   "string_value",
		"test.settings.duration_key": time.Duration(10000),
		"test.server.addr":           "127.0.0.1",
		"test.server.port":           int64(8000),
	}
	if err := c.Load(); err != nil {
		t.Error(err)
	}
	for key, value := range expected {
		switch value.(type) {
		case int64:
			if v, err := c.Value(key).Int(); err != nil {
				t.Error(key, value, err)
			} else if v != value {
				t.Errorf("no expect key: %s value: %v, but got: %v", key, value, v)
			}
		case float64:
			if v, err := c.Value(key).Float(); err != nil {
				t.Error(key, value, err)
			} else if v != value {
				t.Errorf("no expect key: %s value: %v, but got: %v", key, value, v)
			}
		case string:
			if v, err := c.Value(key).String(); err != nil {
				t.Error(key, value, err)
			} else if v != value {
				t.Errorf("no expect key: %s value: %v, but got: %v", key, value, v)
			}
		case time.Duration:
			if v, err := c.Value(key).Duration(); err != nil {
				t.Error(key, value, err)
			} else if v != value {
				t.Errorf("no expect key: %s value: %v, but got: %v", key, value, v)
			}
		}
	}
	// scan
	var settings struct {
		IntKey      int64         `json:"int_key"`
		FloatKey    float64       `json:"float_key"`
		StringKey   string        `json:"string_key"`
		DurationKey time.Duration `json:"duration_key"`
	}
	if err := c.Value("test.settings").Scan(&settings); err != nil {
		t.Error(err)
	}
	if v := expected["test.settings.int_key"]; settings.IntKey != v {
		t.Errorf("no expect int_key value: %v, but got: %v", settings.IntKey, v)
	}
	if v := expected["test.settings.float_key"]; settings.FloatKey != v {
		t.Errorf("no expect float_key value: %v, but got: %v", settings.FloatKey, v)
	}
	if v := expected["test.settings.string_key"]; settings.StringKey != v {
		t.Errorf("no expect string_key value: %v, but got: %v", settings.StringKey, v)
	}
	if v := expected["test.settings.duration_key"]; settings.DurationKey != v {
		t.Errorf("no expect duration_key value: %v, but got: %v", settings.DurationKey, v)
	}

	// not found
	if _, err := c.Value("not_found_key").Bool(); errors.Is(err, config.ErrNotFound) {
		t.Logf("not_found_key not match: %v", err)
	}
}

func testScan(t *testing.T, c config.Config) {
	var conf TestJSON
	if err := c.Load(); err != nil {
		t.Error(err)
	}
	if err := c.Scan(&conf); err != nil {
		t.Error(err)
	}
	t.Log(conf)
}

func TestMergeDataRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test_config.json")
	defer os.Remove(path)
	if err := os.WriteFile(path, []byte(_testJSON), 0o666); err != nil {
		t.Error(err)
	}
	c := config.New(config.WithSource(
		NewSource(new(TestJSON)),
	))
	const count = 80
	wg := &sync.WaitGroup{}
	wg.Add(2)
	startCh := make(chan struct{})
	go func() {
		defer wg.Done()
		<-startCh
		for i := 0; i < count; i++ {
			var conf struct{}
			if err := c.Scan(&conf); err != nil {
				t.Error(err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		<-startCh
		for i := 0; i < count; i++ {
			if err := c.Load(); err != nil {
				t.Error(err)
			}
		}
	}()
	close(startCh)
	wg.Wait()
}
