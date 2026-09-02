package sourcehttp_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
)

var _ = Describe("FlexFloat", func() {
	decode := func(raw string) (sourcehttp.FlexFloat, error) {
		var out struct {
			V sourcehttp.FlexFloat `json:"v"`
		}
		err := json.Unmarshal([]byte(`{"v":`+raw+`}`), &out)
		return out.V, err
	}

	It("accepts a JSON number (Shodan style)", func() {
		v, err := decode(`4.0`)
		Expect(err).ToNot(HaveOccurred())
		Expect(v.Float()).To(Equal(4.0))
	})

	It("accepts a quoted number (Red Hat style)", func() {
		v, err := decode(`"7.8"`)
		Expect(err).ToNot(HaveOccurred())
		Expect(v.Float()).To(Equal(7.8))
	})

	It("treats null as zero", func() {
		v, err := decode(`null`)
		Expect(err).ToNot(HaveOccurred())
		Expect(v.Float()).To(BeZero())
	})

	It("treats an empty string as zero", func() {
		v, err := decode(`""`)
		Expect(err).ToNot(HaveOccurred())
		Expect(v.Float()).To(BeZero())
	})

	It("errors on a non-numeric string", func() {
		_, err := decode(`"not-a-number"`)
		Expect(err).To(HaveOccurred())
	})
})
